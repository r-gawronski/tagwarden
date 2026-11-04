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
	"slices"
	"strings"
	"testing"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

func TestRescan(t *testing.T) {
	const cleanTag, missing = "clean", "missing"
	for _, tc := range []struct {
		name       string
		untag      bool
		untaggable []string
		noDelete   bool
		want       v1alpha1.VulnerableTagAction
		gone       bool
	}{
		{name: "report keeps the tag", want: v1alpha1.VulnerableKept},
		{name: "untag deletes an untaggable tag", untag: true, untaggable: []string{v100}, want: v1alpha1.VulnerableUntagged, gone: true},
		{name: "untag refuses a tag the rules keep", untag: true, untaggable: []string{cleanTag}, want: v1alpha1.VulnerableUntagRefused},
		{name: "untag falls back without tag delete", untag: true, untaggable: []string{v100}, noDelete: true, want: v1alpha1.VulnerableUntagFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The source is empty: a re-scan reads only the target.
			src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{noDelete: tc.noDelete})
			vulnDigest := push(t, dst.repo, v100, image(t))
			cleanDigest := push(t, dst.repo, cleanTag, image(t))
			e := newGate(t, vuln.Policy{Action: vuln.Block}, func(hex string) (string, string) {
				if hex == vulnDigest.Hex {
					return critical, "0"
				}
				return clean, "0"
			})
			// Judged verdicts never skip a re-scan.
			e.gate.Judged = map[string]string{v100: vulnDigest.String(), cleanTag: cleanDigest.String()}
			e.gate.Untag, e.gate.Untaggable = tc.untag, map[string]bool{}
			for _, u := range tc.untaggable {
				e.gate.Untaggable[u] = true
			}
			req := Request{Source: src.repo, Target: dst.repo, Gate: e.gate,
				Policy: tags.Policy{Tags: []string{v100, cleanTag, missing}}}

			res, err := Rescan(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.sidecar.requests(); !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values([]string{vulnDigest.Hex, cleanDigest.Hex}))) {
				t.Fatalf("scanned %v", got)
			}
			if len(res.Copied)+len(res.Blocked)+len(res.Failed) != 0 || src.manifestGets.Load() != 0 {
				t.Fatalf("result %+v, source manifest GETs %d", res, src.manifestGets.Load())
			}
			var vuln Artifact
			for _, a := range slices.Concat(res.Skipped, res.Untagged) {
				if a.Tag == v100 {
					vuln = a
				}
				if !a.Scan.PresentOnTarget {
					t.Errorf("%s: not marked present on target", a.Tag)
				}
			}
			if vuln.Untag != tc.want || vuln.Digest != vulnDigest.String() {
				t.Fatalf("vulnerable tag %+v, want %s", vuln, tc.want)
			}
			_, onTarget := headDigest(t, dst.repo.Tag(v100))
			if onTarget == tc.gone || slices.Contains(tagsOf(res.Untagged), v100) != tc.gone {
				t.Fatalf("tag on target %v, untagged %v, want gone %v", onTarget, tagsOf(res.Untagged), tc.gone)
			}
			if _, ok := headDigest(t, dst.repo.Digest(vulnDigest.String())); !ok {
				t.Fatal("untag deleted the digest")
			}
			if got := tagsOf(res.Skipped); slices.Contains(got, missing) || !slices.Contains(got, cleanTag) {
				t.Fatalf("skipped %v", got)
			}
			if failed := tc.want == v1alpha1.VulnerableUntagFailed; failed != (len(res.Errors) == 1 && strings.Contains(res.Errors[0], "untag failed")) {
				t.Fatalf("errors %v", res.Errors)
			}
		})
	}
}

func TestRescanRefusesPatternsAndUngated(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	e := newGate(t, vuln.Policy{Action: vuln.Report}, always(clean, "0"))
	if _, err := Rescan(context.Background(), Request{Source: src.repo, Target: dst.repo, Gate: e.gate,
		Policy: tags.Policy{Include: []string{".*"}}}); err == nil {
		t.Fatal("pattern policy accepted")
	}
	if _, err := Rescan(context.Background(), Request{Source: src.repo, Target: dst.repo,
		Policy: tags.Policy{Tags: []string{v100}}}); err == nil {
		t.Fatal("ungated rescan accepted")
	}
}
