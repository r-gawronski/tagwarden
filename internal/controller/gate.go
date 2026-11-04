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
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// gate resolves the vulnerability gate of a generated mirror of a gated
// target into s.Gate and the scanner sidecar. Every other mirror gets
// neither and renders as before. ScannerReady does not matter here: a Job
// finds an unreachable or mismatched server itself and applies
// onScanError. Without a usable scanner configuration there is no sidecar
// to render: under onScanError Block the mirror is refused with the
// returned message, so nothing is copied unscanned; under Report it
// renders ungated and copies, as a scan error would.
func (r *ArtifactMirrorReconciler) gate(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, s *syncspec.Spec) (*sidecar, string, error) {
	g := gateOf(t)
	if g == nil || !isGenerated(t, m) {
		return nil, "", nil
	}
	var list mirrorv1alpha1.VulnerabilityExceptionList
	if err := r.List(ctx, &list); err != nil {
		return nil, "", err
	}
	var judged []syncspec.SyncedTag
	var fingerprint string
	if gs := m.Status.Gate; gs != nil {
		fingerprint = gs.JudgedFingerprint
		for _, j := range gs.Judged {
			judged = append(judged, syncspec.SyncedTag{Tag: j.Tag, Digest: j.Digest})
		}
	}
	_, problem := effectiveScanner(g.Scanner, r.Scanner)
	var out *syncspec.Gate
	if problem == "" {
		var err error
		out, err = syncspec.NewGate(g, syncspec.ScannerDefaults{URL: r.Scanner.URL, Version: r.Scanner.Version, Image: r.Scanner.Image},
			cmp.Or(r.ClusterDomain, DefaultClusterDomain), activeExceptions(list.Items, t, m, time.Now()), judged, fingerprint)
		if err != nil {
			problem = "invalid scanner URL"
		}
	}
	if problem != "" {
		if g.OnScanError == mirrorv1alpha1.GateActionBlock {
			return nil, fmt.Sprintf("the vulnerability gate of ClusterMirrorTarget %s cannot scan (%s) and onScanError is Block", t.Name, problem), nil
		}
		return nil, "", nil
	}
	s.Gate = out
	sc := &sidecar{gate: out, scanner: g.Scanner}
	switch {
	case g.Scanner != nil && g.Scanner.TokenSecretRef != nil:
		sc.token = g.Scanner.TokenSecretRef
	case r.Scanner.TokenSecret != "":
		sc.token = &mirrorv1alpha1.TokenSecretKeyRef{Name: r.Scanner.TokenSecret, Key: defaultTokenKey}
	}
	return sc, "", nil
}

// activeExceptions returns the exceptions that apply to m at now, sorted by
// name so the spec does not change with list order: same target, m's
// namespace and source, not expired and within maxExceptionDuration. The
// Job checks expiry again against its own clock.
func activeExceptions(excs []mirrorv1alpha1.VulnerabilityException, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror, now time.Time) []mirrorv1alpha1.VulnerabilityException {
	maxDuration := defaultMaxExceptionDuration
	if g := gateOf(t); g != nil && g.MaxExceptionDuration != nil {
		maxDuration = g.MaxExceptionDuration.Duration
	}
	src := canonicalSource(m.Spec.Source)
	var out []mirrorv1alpha1.VulnerabilityException
	for _, e := range excs {
		if e.Spec.TargetRef == t.Name && slices.Contains(e.Spec.Namespaces, m.Namespace) && e.Spec.Repository == src &&
			e.DeletionTimestamp.IsZero() && now.Before(e.Spec.Expires.Time) && !e.Spec.Expires.After(e.CreationTimestamp.Add(maxDuration)) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b mirrorv1alpha1.VulnerabilityException) int { return strings.Compare(a.Name, b.Name) })
	return out
}
