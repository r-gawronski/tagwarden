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
	"slices"
	"strings"
	"testing"

	"github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

const (
	v110 = "v1.1.0"
	v120 = "v1.2.0"
	v130 = "v1.3.0"
)

// pruneFixture mirrors v1.1.0 to v1.3.0 into the target, then returns a
// request that selects the two newest tags and may prune v1.1.0, which the
// mirror owns.
func pruneFixture(t *testing.T, dstOpts regOpts) (src, dst *testRegistry, req Request, owned Artifact) {
	t.Helper()
	src, dst = newRegistry(t, regOpts{}), newRegistry(t, dstOpts)
	for _, tag := range []string{v100, v110, v120, v130} {
		push(t, src.repo, tag, image(t))
	}
	if res, err := Run(context.Background(), Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{KeepLatest: 3}}); err != nil {
		t.Fatalf("first run: %v (%+v)", err, res)
	}
	d, _ := headDigest(t, dst.repo.Tag(v110))
	owned = Artifact{Tag: v110, Digest: d}
	return src, dst, Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{KeepLatest: 2}, Prunable: []Artifact{owned}}, owned
}

func targetTags(t *testing.T, dst *testRegistry) []string { return list(t, dst.repo) }

func TestPrunesTagsOutsideTheSelection(t *testing.T) {
	_, dst, req, owned := pruneFixture(t, regOpts{})
	// Not owned, so never pruned, and owned but still selected.
	push(t, dst.repo, "manual", image(t))
	req.Prunable = append(req.Prunable, Artifact{Tag: v130, Digest: "sha256:" + strings.Repeat("1", 64)})
	var deleted []string
	req.DeleteTag = func(ctx context.Context, tag, digest string) error {
		deleted = append(deleted, tag+"@"+digest)
		return nil
	}
	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run: %v (%+v)", err, res)
	}
	if len(res.Pruned) != 1 || res.Pruned[0].Tag != v110 || res.Pruned[0].Digest != owned.Digest || len(res.Dropped) != 0 {
		t.Errorf("pruned %+v dropped %+v", res.Pruned, res.Dropped)
	}
	if !slices.Equal(deleted, []string{v110 + "@" + owned.Digest}) {
		t.Errorf("deleted %v", deleted)
	}
}

func TestPruneDeletesOnTheRegistry(t *testing.T) {
	_, dst, req, owned := pruneFixture(t, regOpts{})
	manual := push(t, dst.repo, "manual", image(t))
	res, err := Run(context.Background(), req)
	if err != nil || len(res.Errors) != 0 {
		t.Fatalf("Run: %v (%+v)", err, res)
	}
	if got := targetTags(t, dst); !slices.Equal(got, []string{"manual", v120, v130}) {
		t.Errorf("target tags %v", got)
	}
	if got, _ := headDigest(t, dst.repo.Tag("manual")); got != manual.String() {
		t.Errorf("manual tag digest %s", got)
	}
	// Only the tag goes: the digest stays.
	if _, ok := headDigest(t, dst.repo.Digest(owned.Digest)); !ok {
		t.Error("digest was deleted with the tag")
	}
	if len(res.Pruned) != 1 || res.Pruned[0].Tag != v110 {
		t.Errorf("pruned %+v", res.Pruned)
	}
	// A second run finds the tag gone and prunes nothing.
	res, err = Run(context.Background(), req)
	if err != nil || len(res.Pruned) != 0 || len(res.Dropped) != 1 || !sameTag(res.Dropped[0], owned) {
		t.Errorf("second run: %v pruned %+v dropped %+v", err, res.Pruned, res.Dropped)
	}
}

func TestPruneKeepsAMovedTag(t *testing.T) {
	_, dst, req, owned := pruneFixture(t, regOpts{})
	moved := push(t, dst.repo, v110, image(t))
	writes := dst.writes.Load()
	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pruned) != 0 || len(res.Dropped) != 1 || !sameTag(res.Dropped[0], owned) {
		t.Errorf("pruned %+v dropped %+v", res.Pruned, res.Dropped)
	}
	if got, _ := headDigest(t, dst.repo.Tag(v110)); got != moved.String() {
		t.Errorf("moved tag digest %s, want %s", got, moved)
	}
	if dst.writes.Load() != writes {
		t.Error("the target was written")
	}
}

func TestPruneSkipsTheStep(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(t *testing.T, src, dst *testRegistry, req *Request)
	}{
		{"listing failed", func(t *testing.T, src, dst *testRegistry, req *Request) { src.listFailing.Store(true) }},
		{"empty selection", func(t *testing.T, src, dst *testRegistry, req *Request) {
			req.Policy = tags.Policy{SemverRange: ">=9.0.0"}
		}},
		{"failed copy", func(t *testing.T, src, dst *testRegistry, req *Request) {
			push(t, src.repo, "v1.4.0", index(t, "linux/amd64"))
			req.RequiredPlatforms = []string{"linux/s390x"}
		}},
		{"refused mutation", func(t *testing.T, src, dst *testRegistry, req *Request) {
			push(t, dst.repo, v130, image(t))
		}},
		{"blocked tag", func(t *testing.T, src, dst *testRegistry, req *Request) {
			push(t, src.repo, "v1.4.0", image(t))
			req.Gate = newGate(t, vuln.Policy{Action: vuln.Block}, func(string) (string, string) { return critical, "0" }).gate
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst, req, _ := pruneFixture(t, regOpts{})
			tc.prep(t, src, dst, &req)
			before := targetTags(t, dst)
			writes := dst.writes.Load()
			res, err := Run(context.Background(), req)
			if tc.name != "empty selection" && tc.name != "blocked tag" && err == nil {
				t.Fatalf("want an error, got %+v", res)
			}
			if len(res.Pruned) != 0 || len(res.Dropped) != 0 {
				t.Errorf("pruned %+v dropped %+v", res.Pruned, res.Dropped)
			}
			if got := targetTags(t, dst); !slices.Equal(got, before) {
				t.Errorf("target tags %v, want %v", got, before)
			}
			if tc.name != "failed copy" && tc.name != "blocked tag" && dst.writes.Load() != writes {
				t.Error("the target was written")
			}
		})
	}
}

// A listing that is valid but lacks the newest tags must not prune them.
func TestPruneKeepsTagsAPartialListingHides(t *testing.T) {
	_, dst, req, _ := pruneFixture(t, regOpts{})
	partial := newRegistry(t, regOpts{})
	push(t, partial.repo, v100, image(t))
	push(t, partial.repo, "v1.0.1", image(t))
	req.Source = partial.repo
	for _, tag := range []string{v120, v130} {
		d, _ := headDigest(t, dst.repo.Tag(tag))
		req.Prunable = append(req.Prunable, Artifact{Tag: tag, Digest: d})
	}
	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run: %v (%+v)", err, res)
	}
	if len(res.Pruned) != 1 || res.Pruned[0].Tag != v110 {
		t.Errorf("pruned %+v, want only %s", res.Pruned, v110)
	}
	got := targetTags(t, dst)
	for _, tag := range []string{v120, v130} {
		if !slices.Contains(got, tag) {
			t.Errorf("%s was pruned: %v", tag, got)
		}
	}
	if len(res.Errors) != 2 || !strings.HasPrefix(res.Errors[0], v120+": prune kept") {
		t.Errorf("errors %v", res.Errors)
	}
}

func TestPruneFailedDeleteIsKept(t *testing.T) {
	_, dst, req, owned := pruneFixture(t, regOpts{noDelete: true})
	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("a failed prune must not fail the run: %v", err)
	}
	if len(res.Pruned) != 0 || len(res.Dropped) != 0 {
		t.Errorf("pruned %+v dropped %+v", res.Pruned, res.Dropped)
	}
	if len(res.Errors) != 1 || !strings.HasPrefix(res.Errors[0], v110+": prune failed, kept: ") {
		t.Errorf("errors %v", res.Errors)
	}
	if got, _ := headDigest(t, dst.repo.Tag(v110)); got != owned.Digest {
		t.Errorf("tag digest %s", got)
	}
}

func TestPruneDeleterNotFoundDropsTheTag(t *testing.T) {
	_, _, req, owned := pruneFixture(t, regOpts{})
	req.DeleteTag = func(context.Context, string, string) error { return registry.ErrTagNotFound }
	res, err := Run(context.Background(), req)
	if err != nil || len(res.Pruned) != 0 || len(res.Dropped) != 1 || !sameTag(res.Dropped[0], owned) || len(res.Errors) != 0 {
		t.Errorf("%v: pruned %+v dropped %+v errors %v", err, res.Pruned, res.Dropped, res.Errors)
	}
	req.DeleteTag = func(context.Context, string, string) error { return errors.New("HTTP 500") }
	res, err = Run(context.Background(), req)
	if err != nil || len(res.Pruned) != 0 || len(res.Dropped) != 0 || len(res.Errors) != 1 {
		t.Errorf("%v: pruned %+v dropped %+v errors %v", err, res.Pruned, res.Dropped, res.Errors)
	}
}

func sameTag(a, b Artifact) bool { return a.Tag == b.Tag && a.Digest == b.Digest }
