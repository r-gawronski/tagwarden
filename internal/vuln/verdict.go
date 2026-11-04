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
	"cmp"
	"slices"
	"time"
)

// Limits on what a Result carries.
const (
	MaxTopIDs   = 5   // status.findings topIDs
	MaxAuditIDs = 200 // ids per platform in the audit line
)

// Action is what to do with a tag.
type Action string

// Actions. The zero value behaves as Report.
const (
	Report Action = "Report"
	Block  Action = "Block"
)

// Verdict is the judgement of one platform or of a whole tag.
type Verdict string

// Verdicts, as in the design.
const (
	Passed        Verdict = "passed"
	Accepted      Verdict = "accepted"
	FindingsFound Verdict = "findings"
	ScanError     Verdict = "scan-error"
)

// Policy is the vulnerability gate policy of a target. Step 5 maps
// autoMirror.vulnerabilityGate onto it. The zero Severity means Critical.
type Policy struct {
	Action         Action
	Severity       Severity
	IgnoreUnfixed  bool
	IncludeUnknown bool
	OnScanError    Action
}

// Exception is a security exception. Step 5 maps VulnerabilityException onto
// it. An exception with neither Digests nor Vulnerabilities matches nothing.
type Exception struct {
	Name            string
	Namespaces      []string
	Repository      string
	Digests         []string // index or platform digest; empty: any digest
	Vulnerabilities []string // exact IDs; empty: every finding
	Expires         time.Time
}

// Subject identifies the mirror and artifact being judged.
type Subject struct {
	Namespace  string
	Repository string // canonical source repository
	Digest     string // index digest, or the manifest digest of a single image
}

// PlatformInput is the scan outcome of one image manifest.
type PlatformInput struct {
	Platform  string // for example linux/amd64
	Digest    string
	Findings  []Finding
	ScanError string // reason code; non-empty means the scan failed
}

// AcceptedFinding is a finding covered by an exception.
type AcceptedFinding struct {
	ID        string
	Exception string
}

// PlatformResult is the verdict of one platform.
type PlatformResult struct {
	Platform          string
	Digest            string
	Verdict           Verdict
	Counts            map[Severity]int // every reported finding
	Highest           Severity         // empty when there are no findings
	IDs               []string         // uncovered counting IDs, worst first, up to MaxAuditIDs
	IDsTruncated      bool
	Accepted          []AcceptedFinding // deduped by ID, up to MaxAuditIDs
	AcceptedTruncated bool
	ScanError         string
	JavaScanned       bool
}

// Result is the verdict of a tag.
type Result struct {
	Verdict     Verdict
	Block       bool   // do not mirror the tag
	Reason      string // first scan error reason, if any platform had one
	Platforms   []PlatformResult
	Counts      map[Severity]int // per severity, the largest value over platforms
	Highest     Severity
	TopIDs      []string // up to MaxTopIDs, worst first
	JavaScanned bool
}

// Layer media types of attestations: in-toto statements and DSSE envelopes.
var attestationLayers = []string{
	"application/vnd.in-toto+json",
	"application/vnd.dsse.envelope.v1+json",
}

// supplyChainLayers are attestation, signature and SBOM layer media types.
var supplyChainLayers = append(slices.Clone(attestationLayers),
	"application/vnd.dev.cosign.simplesigning.v1+json",
	"application/vnd.dev.sigstore.bundle.v0.3+json",
	"application/spdx+json",
	"text/spdx",
	"application/vnd.cyclonedx+json",
	"application/vnd.cyclonedx+xml",
)

// SkipManifest reports whether an image manifest with these layer media
// types is an attestation, not an image to scan: it has layers and all of
// them are in-toto or DSSE. The platform (unknown/unknown) and the
// attestation annotation are publisher-controlled and never decide.
func SkipManifest(layers []string) bool { return onlyOf(layers, attestationLayers) }

// SupplyChainArtifact reports whether a referrer or cosign tag-scheme
// manifest with these layer media types holds only signatures,
// attestations or SBOMs, so the gate may copy it without a scan.
func SupplyChainArtifact(layers []string) bool { return onlyOf(layers, supplyChainLayers) }

func onlyOf(layers, allowed []string) bool {
	return len(layers) > 0 && !slices.ContainsFunc(layers, func(l string) bool { return !slices.Contains(allowed, l) })
}

// Evaluate judges a tag from the scan outcomes of its image manifests. The
// whole index is copied or not, so any platform whose outcome blocks blocks
// the tag. With findings and scan errors mixed, Verdict is findings and
// Reason carries the scan error. No platforms is a scan error.
func Evaluate(p Policy, excs []Exception, s Subject, in []PlatformInput, javaScanned bool, now time.Time) Result {
	res := Result{Verdict: Passed, JavaScanned: javaScanned, Counts: map[Severity]int{}}
	if len(in) == 0 {
		res.Verdict, res.Reason = ScanError, "NoPlatforms"
		res.Block = p.OnScanError == Block
		return res
	}
	var top []Finding
	for _, pi := range in {
		pr, counting := platform(p, excs, s, pi, javaScanned, now)
		top = append(top, counting...)
		res.Platforms = append(res.Platforms, pr)
		if pr.Verdict == ScanError {
			res.Block = res.Block || p.OnScanError == Block
			if res.Reason == "" {
				res.Reason = pr.ScanError
			}
		}
		if pr.Verdict == FindingsFound {
			res.Block = res.Block || p.Action == Block
		}
		res.Verdict = worse(res.Verdict, pr.Verdict)
		for sev, n := range pr.Counts {
			res.Counts[sev] = max(res.Counts[sev], n)
		}
		if pr.Highest.rank() > res.Highest.rank() {
			res.Highest = pr.Highest
		}
	}
	res.TopIDs = rank(top, MaxTopIDs)
	return res
}

// worse orders verdicts: passed < accepted < scan-error < findings.
func worse(a, b Verdict) Verdict {
	order := map[Verdict]int{Passed: 0, Accepted: 1, ScanError: 2, FindingsFound: 3}
	if order[b] > order[a] {
		return b
	}
	return a
}

func platform(p Policy, excs []Exception, s Subject, in PlatformInput, javaScanned bool, now time.Time) (PlatformResult, []Finding) {
	pr := PlatformResult{Platform: in.Platform, Digest: in.Digest, Counts: map[Severity]int{}, JavaScanned: javaScanned}
	if in.ScanError != "" {
		pr.Verdict, pr.ScanError = ScanError, in.ScanError
		return pr, nil
	}
	var counting []Finding
	anyAccepted := false
	acceptedSeen := map[string]bool{}
	for _, f := range in.Findings {
		if p.IgnoreUnfixed && f.Fix == "" && f.Status != "fixed" {
			continue
		}
		pr.Counts[f.Severity]++
		if f.Severity.rank() > pr.Highest.rank() {
			pr.Highest = f.Severity
		}
		if !counts(p, f.Severity) {
			continue
		}
		if name, ok := covered(excs, s, in.Digest, f.ID, now); ok {
			anyAccepted = true
			switch {
			case acceptedSeen[f.ID]:
			case len(pr.Accepted) == MaxAuditIDs:
				pr.AcceptedTruncated = true
			default:
				acceptedSeen[f.ID] = true
				pr.Accepted = append(pr.Accepted, AcceptedFinding{ID: f.ID, Exception: name})
			}
			continue
		}
		counting = append(counting, f)
	}
	switch {
	case len(counting) > 0:
		pr.Verdict = FindingsFound
	case anyAccepted:
		pr.Verdict = Accepted
	default:
		pr.Verdict = Passed
	}
	pr.IDs = rank(counting, MaxAuditIDs+1)
	if len(pr.IDs) > MaxAuditIDs {
		pr.IDs, pr.IDsTruncated = pr.IDs[:MaxAuditIDs], true
	}
	return pr, counting
}

// counts reports whether a finding of this severity counts against the policy.
func counts(p Policy, sev Severity) bool {
	if sev == Unknown {
		return p.IncludeUnknown
	}
	th := p.Severity
	if th == "" {
		th = Critical
	}
	return sev.rank() >= th.rank()
}

// covered returns the name of the first (by name) active exception covering
// the finding.
func covered(excs []Exception, s Subject, digest, id string, now time.Time) (string, bool) {
	name, found := "", false
	for _, e := range excs {
		if !matches(e, s, digest, id, now) || (found && e.Name >= name) {
			continue
		}
		name, found = e.Name, true
	}
	return name, found
}

func matches(e Exception, s Subject, digest, id string, now time.Time) bool {
	if len(e.Digests) == 0 && len(e.Vulnerabilities) == 0 {
		return false
	}
	return now.Before(e.Expires) &&
		e.Repository == s.Repository &&
		slices.Contains(e.Namespaces, s.Namespace) &&
		(len(e.Digests) == 0 || slices.Contains(e.Digests, s.Digest) || slices.Contains(e.Digests, digest)) &&
		(len(e.Vulnerabilities) == 0 || slices.Contains(e.Vulnerabilities, id))
}

// rank returns the distinct IDs, worst severity first then by ID, up to n.
func rank(fs []Finding, n int) []string {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(b.Severity.rank(), a.Severity.rank()), cmp.Compare(a.ID, b.ID))
	})
	var out []string
	for _, f := range fs {
		if len(out) == n {
			break
		}
		if len(out) == 0 || !slices.Contains(out, f.ID) {
			out = append(out, f.ID)
		}
	}
	return out
}
