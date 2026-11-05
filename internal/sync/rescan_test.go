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
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/registry"
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
		// deleter, when set, becomes Request.DeleteTag.
		deleter func(dst *testRegistry) func(ctx context.Context, tag, digest string) error
		want    v1alpha1.VulnerableTagAction
		gone    bool
		// wantErr is the one entry res.Errors must hold; UntagFailed
		// implies "untag failed".
		wantErr string
	}{
		{name: "report keeps the tag", want: v1alpha1.VulnerableKept},
		{name: "untag deletes an untaggable tag", untag: true, untaggable: []string{v100}, want: v1alpha1.VulnerableUntagged, gone: true},
		{name: "untag refuses a tag the rules keep", untag: true, untaggable: []string{cleanTag}, want: v1alpha1.VulnerableUntagRefused},
		{name: "untag falls back without tag delete", untag: true, untaggable: []string{v100}, noDelete: true, want: v1alpha1.VulnerableUntagFailed},
		{name: "untag uses the target deleter", untag: true, untaggable: []string{v100}, noDelete: true,
			deleter: func(dst *testRegistry) func(context.Context, string, string) error {
				return func(_ context.Context, tag, _ string) error {
					// Delete on the registry itself, past the noDelete hook.
					rec := httptest.NewRecorder()
					dst.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v2/"+dst.repo.RepositoryStr()+"/manifests/"+tag, nil))
					if rec.Code != http.StatusAccepted {
						return errors.New(rec.Result().Status)
					}
					return nil
				}
			}, want: v1alpha1.VulnerableUntagged, gone: true},
		{name: "untag refuses a tag the deleter does not find", untag: true, untaggable: []string{v100}, noDelete: true,
			deleter: func(*testRegistry) func(context.Context, string, string) error {
				return func(context.Context, string, string) error { return registry.ErrTagNotFound }
			}, want: v1alpha1.VulnerableUntagRefused, wantErr: "untag refused"},
		{name: "untag reports a deleter failure", untag: true, untaggable: []string{v100}, noDelete: true,
			deleter: func(*testRegistry) func(context.Context, string, string) error {
				return func(context.Context, string, string) error { return errors.New("HTTP 500") }
			}, want: v1alpha1.VulnerableUntagFailed},
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
			var deleted []string
			if tc.deleter != nil {
				del := tc.deleter(dst)
				req.DeleteTag = func(ctx context.Context, tag, digest string) error {
					deleted = append(deleted, tag, digest)
					return del(ctx, tag, digest)
				}
			}

			res, err := Rescan(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if tc.deleter != nil && !slices.Equal(deleted, []string{v100, vulnDigest.String()}) {
				t.Fatalf("deleter got %v", deleted)
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
			wantErr := tc.wantErr
			if tc.want == v1alpha1.VulnerableUntagFailed {
				wantErr = "untag failed"
			}
			if wantErr == "" && len(res.Errors) != 0 || wantErr != "" && (len(res.Errors) != 1 || !strings.Contains(res.Errors[0], wantErr)) {
				t.Fatalf("errors %v, want one with %q", res.Errors, wantErr)
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

func TestRescanRefusesMovedTag(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	d := push(t, dst.repo, v100, image(t))
	var moved v1.Hash
	e := newGate(t, vuln.Policy{Action: vuln.Block}, func(string) (string, string) {
		// A sync moves the tag after the scan read it.
		if moved.Hex == "" {
			moved = push(t, dst.repo, v100, image(t))
		}
		return critical, "0"
	})
	e.gate.Untag, e.gate.Untaggable = true, map[string]bool{v100: true}
	res, err := Rescan(context.Background(), Request{Source: src.repo, Target: dst.repo, Gate: e.gate,
		Policy: tags.Policy{Tags: []string{v100}}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := headDigest(t, dst.repo.Tag(v100)); !ok || got != moved.String() || got == d.String() {
		t.Fatalf("tag %q on target %v, want the moved digest %s", got, ok, moved)
	}
	if len(res.Untagged) != 0 || len(res.Skipped) != 1 || res.Skipped[0].Untag != v1alpha1.VulnerableUntagRefused {
		t.Fatalf("result %+v", res)
	}
}

func TestRescanFailsOnScanError(t *testing.T) {
	src, dst := newRegistry(t, regOpts{}), newRegistry(t, regOpts{})
	push(t, dst.repo, v100, image(t))
	e := newGate(t, vuln.Policy{Action: vuln.Block}, always("not json", "0"))
	res, err := Rescan(context.Background(), Request{Source: src.repo, Target: dst.repo, Gate: e.gate,
		Policy: tags.Policy{Tags: []string{v100}}})
	var sb *ScanBlockedError
	if !errors.As(err, &sb) || len(res.Errors) != 1 {
		t.Fatalf("err %v, result %+v", err, res)
	}
}
