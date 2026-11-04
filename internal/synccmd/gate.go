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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/sync"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

// newGate builds the gate of a run. The Trivy server is an internal
// address set by the platform team, so its client goes direct, never
// through the proxy, and follows no redirects. The source checks (T16)
// guard the source path only.
func newGate(spec syncspec.Spec, p options) (*sync.Gate, error) {
	g := spec.Gate
	ca, err := readOptional(p.scannerCA)
	if err != nil {
		return nil, err
	}
	t, err := registry.NewTransport(registry.Options{CAPEM: ca, NoEnvProxy: true, Window: p.window})
	if err != nil {
		return nil, fmt.Errorf("scanner transport: %w", err)
	}
	recorded := map[string]string{}
	for _, r := range g.Recorded {
		recorded[r.Tag] = r.Digest
	}
	out := &sync.Gate{
		Policy:     g.Policy(),
		Exceptions: g.VulnExceptions(),
		Namespace:  spec.Mirror.Namespace,
		Repository: syncspec.CanonicalRegistry(spec.SourceRepo.RegistryStr()) + "/" + spec.SourceRepo.RepositoryStr(),
		Recorded:   recorded,
		LayoutDir:  p.layoutDir,
		ScanDir:    p.scanDir,
		ServerURL:  g.Scanner.URL,
		Client: &http.Client{
			Transport:     t,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Version:  g.Scanner.Version,
		MaxDBAge: g.MaxDBAge.Duration,
		Timeout:  g.Scanner.Timeout.Duration,
	}
	if g.Scanner.JavaDB == v1alpha1.JavaDBPerJob {
		tag, err := name.NewTag(g.Scanner.JavaDBRepository, name.StrictValidation)
		if err != nil {
			return nil, err
		}
		out.JavaDB = &tag
	}
	return out, nil
}

// notRetryable maps a run whose only problem is tags blocked by a stale DB
// or a version mismatch to ExitConfig: a retry cannot get a verdict until
// the platform updates the DB or the scanner. Scanner errors such as a
// timeout keep ExitSyncFailed, so the Job retries.
func notRetryable(ctx context.Context, err error, res sync.Result) bool {
	var sb *sync.ScanBlockedError
	return errors.As(err, &sb) && !sb.Retryable() && ctx.Err() == nil &&
		len(res.Failed) == 0 && !errors.Is(err, sync.ErrTagMutated)
}

var severityNames = map[vuln.Severity]v1alpha1.Severity{
	vuln.Critical: v1alpha1.SeverityCritical, vuln.High: v1alpha1.SeverityHigh, vuln.Medium: v1alpha1.SeverityMedium,
	vuln.Low: v1alpha1.SeverityLow, vuln.Unknown: v1alpha1.SeverityUnknown,
}

// gateSummary adds the version 2 fields of a gated run to r.
func gateSummary(r *report, res sync.Result) {
	r.V = syncspec.ReportVersionGate
	r.Gate = res.Gate
	r.JavaScanned = &res.JavaScanned
	r.Blocked = len(res.Blocked)
	scans := map[string]sync.Artifact{}
	for _, as := range [][]sync.Artifact{res.Skipped, res.Copied, res.Blocked} {
		for _, a := range as {
			if a.Scan != nil {
				scans[a.Tag] = a
			}
		}
	}
	for _, tag := range res.Selected {
		a, ok := scans[tag]
		if !ok {
			continue
		}
		sc := a.Scan
		switch sc.Verdict {
		case vuln.FindingsFound:
			r.Findings++
		case vuln.ScanError:
			r.ScanErrors++
		case vuln.Accepted:
			r.Accepted++
			continue
		default:
			continue
		}
		f := syncspec.TagFinding{
			Tag: tag, Digest: a.Digest,
			Verdict: v1alpha1.VerdictFindings, Outcome: v1alpha1.OutcomeCopied,
			PresentOnTarget: sc.PresentOnTarget,
			Severity:        severityNames[sc.Highest],
			Counts: v1alpha1.SeverityCounts{
				Critical: count(sc.Counts[vuln.Critical]), High: count(sc.Counts[vuln.High]),
				Medium: count(sc.Counts[vuln.Medium]), Low: count(sc.Counts[vuln.Low]), Unknown: count(sc.Counts[vuln.Unknown]),
			},
			ScannedAt: sc.ScannedAt.UTC().Truncate(time.Second),
		}
		if sc.Verdict == vuln.ScanError {
			f.Verdict, f.ScanError = v1alpha1.VerdictScanError, sc.Reason
		}
		if sc.Block {
			f.Outcome = v1alpha1.OutcomeBlocked
		}
		if !sc.DBUpdatedAt.IsZero() {
			f.DBUpdatedAt = sc.DBUpdatedAt.UTC().Format(time.RFC3339)
		}
		// Status keeps only IDs that fit its pattern; the audit line has all.
		for _, id := range sc.TopIDs {
			if len(f.TopIDs) < syncspec.MaxReportIDs && syncspec.VulnID(id) {
				f.TopIDs = append(f.TopIDs, id)
			}
		}
		r.TagFindings = append(r.TagFindings, f)
	}
}

func count(n int) int32 { return int32(min(n, 1<<31-1)) } //nolint:gosec // capped

type auditScan struct {
	Verdict         string          `json:"verdict"`
	Outcome         string          `json:"outcome"`
	PresentOnTarget bool            `json:"presentOnTarget,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	Detail          string          `json:"detail,omitempty"`
	Scanner         auditScanner    `json:"scanner"`
	DB              *auditDB        `json:"db,omitempty"`
	JavaScanned     bool            `json:"javaScanned"`
	Policy          auditPolicy     `json:"policy"`
	Platforms       []auditPlatform `json:"platforms,omitempty"`
}

type auditScanner struct {
	URL     string `json:"url"`
	Version string `json:"version"`
	Image   string `json:"image,omitempty"`
}

type auditDB struct {
	UpdatedAt string `json:"updatedAt"`
}

type auditPolicy struct {
	Action         string `json:"action"`
	Severity       string `json:"severity"`
	IgnoreUnfixed  bool   `json:"ignoreUnfixed"`
	IncludeUnknown bool   `json:"includeUnknown"`
	OnScanError    string `json:"onScanError"`
}

type auditPlatform struct {
	Platform          string          `json:"platform,omitempty"`
	Digest            string          `json:"digest"`
	Verdict           string          `json:"verdict"`
	Counts            map[string]int  `json:"counts,omitempty"`
	IDs               []string        `json:"ids,omitempty"`
	IDsTruncated      bool            `json:"idsTruncated,omitempty"`
	Accepted          []auditAccepted `json:"accepted,omitempty"`
	AcceptedTruncated bool            `json:"acceptedTruncated,omitempty"`
	ScanError         string          `json:"scanError,omitempty"`
}

type auditAccepted struct {
	ID        string `json:"id"`
	Exception string `json:"exception"`
}

// newAuditScan is the full gate detail of a tag for the audit line.
func newAuditScan(g *syncspec.Gate, sc *sync.Scan) *auditScan {
	if g == nil || sc == nil {
		return nil
	}
	a := &auditScan{
		Verdict: string(sc.Verdict), Outcome: "copied", PresentOnTarget: sc.PresentOnTarget,
		Reason: sc.Reason, Detail: sc.Detail,
		Scanner:     auditScanner{URL: g.Scanner.URL, Version: g.Scanner.Version, Image: g.Scanner.Image},
		JavaScanned: sc.JavaScanned,
		Policy: auditPolicy{
			Action: string(g.Action), Severity: string(g.Severity), IgnoreUnfixed: g.IgnoreUnfixed,
			IncludeUnknown: g.IncludeUnknown, OnScanError: string(g.OnScanError),
		},
	}
	if sc.Block {
		a.Outcome = "blocked"
	}
	if !sc.DBUpdatedAt.IsZero() {
		a.DB = &auditDB{UpdatedAt: sc.DBUpdatedAt.UTC().Format(time.RFC3339)}
	}
	for _, p := range sc.Platforms {
		ap := auditPlatform{
			Platform: p.Platform, Digest: p.Digest, Verdict: string(p.Verdict),
			IDs: p.IDs, IDsTruncated: p.IDsTruncated, AcceptedTruncated: p.AcceptedTruncated, ScanError: p.ScanError,
		}
		for sev, n := range p.Counts {
			if ap.Counts == nil {
				ap.Counts = map[string]int{}
			}
			ap.Counts[string(sev)] = n
		}
		for _, x := range p.Accepted {
			ap.Accepted = append(ap.Accepted, auditAccepted{ID: x.ID, Exception: x.Exception})
		}
		a.Platforms = append(a.Platforms, ap)
	}
	return a
}
