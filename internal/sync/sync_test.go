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
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	stdsync "sync"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
)

const (
	v100     = "v1.0.0"
	user     = "puller"
	password = "s3cret-registry-pass"
)

// testRegistry is an in-process registry that counts write requests.
type testRegistry struct {
	repo   name.Repository
	writes atomic.Int32
	// manifestGets counts GET requests for manifests.
	manifestGets atomic.Int32
	// headStatus, when set, answers every manifest HEAD with this status.
	headStatus atomic.Int32
	mu         stdsync.Mutex
	// puts lists the paths of manifest PUT requests.
	puts []string
}

func (r *testRegistry) manifestPuts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.puts)
}

type regOpts struct {
	referrers bool
	// auth requires basic auth.
	auth bool
	// noHeadDigest drops Docker-Content-Digest from HEAD responses.
	noHeadDigest bool
}

func newRegistry(t *testing.T, o regOpts) *testRegistry {
	t.Helper()
	r := &testRegistry{}
	h := registry.New(registry.WithReferrersSupport(o.referrers), registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); o.auth && (!ok || u != user || p != password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			r.writes.Add(1)
		}
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/manifests/") {
			r.manifestGets.Add(1)
		}
		if code := r.headStatus.Load(); code != 0 && req.Method == http.MethodHead && strings.Contains(req.URL.Path, "/manifests/") {
			w.WriteHeader(int(code))
			return
		}
		if req.Method == http.MethodPut && strings.Contains(req.URL.Path, "/manifests/") {
			r.mu.Lock()
			r.puts = append(r.puts, req.URL.Path)
			r.mu.Unlock()
		}
		if o.noHeadDigest && req.Method == http.MethodHead {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			maps.Copy(w.Header(), rec.Header())
			w.Header().Del("Docker-Content-Digest")
			w.WriteHeader(rec.Code)
			return
		}
		h.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/team/app")
	if err != nil {
		t.Fatal(err)
	}
	r.repo = repo
	return r
}

// must panics on setup errors, which fails the test.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func image(t *testing.T) v1.Image {
	t.Helper()
	return must(random.Image(64, 1))
}

func index(t *testing.T, platforms ...string) v1.ImageIndex {
	t.Helper()
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	for _, p := range platforms {
		pl := must(v1.ParsePlatform(p))
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: image(t), Descriptor: v1.Descriptor{Platform: pl}})
	}
	return idx
}

func digestOf(t *testing.T, d partial.Describable) v1.Hash {
	t.Helper()
	return must(d.Digest())
}

func push(t *testing.T, repo name.Repository, tag string, m remote.Taggable, opts ...remote.Option) v1.Hash {
	t.Helper()
	switch v := m.(type) {
	case v1.ImageIndex:
		if err := remote.WriteIndex(repo.Tag(tag), v, opts...); err != nil {
			t.Fatal(err)
		}
		return digestOf(t, v)
	case v1.Image:
		if err := remote.Write(repo.Tag(tag), v, opts...); err != nil {
			t.Fatal(err)
		}
		return digestOf(t, v)
	}
	t.Fatalf("unsupported %T", m)
	return v1.Hash{}
}

// pushReferrer pushes an artifact whose subject is d.
func pushReferrer(t *testing.T, repo name.Repository, subject v1.Descriptor) v1.Hash {
	t.Helper()
	ref := mutate.Subject(image(t), subject).(v1.Image)
	h := digestOf(t, ref)
	if err := remote.Write(repo.Digest(h.String()), ref); err != nil {
		t.Fatal(err)
	}
	return h
}

func headDigest(t *testing.T, ref name.Reference) (string, bool) {
	t.Helper()
	d, err := remote.Head(ref)
	if err != nil {
		return "", false
	}
	return d.Digest.String(), true
}

func list(t *testing.T, repo name.Repository) []string {
	t.Helper()
	ts := must(remote.List(repo))
	slices.Sort(ts)
	return ts
}

func tagsOf(as []Artifact) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Tag)
	}
	slices.Sort(out)
	return out
}

func fallbackTag(h v1.Hash) string { return h.Algorithm + "-" + h.Hex }

func TestRunCopiesSelectedTagsByDigest(t *testing.T) {
	src := newRegistry(t, regOpts{referrers: true})
	dst := newRegistry(t, regOpts{referrers: true})

	idx := index(t, "linux/amd64", "linux/arm64")
	digests := map[string]v1.Hash{}
	for _, tag := range []string{v100, "v1.1.0", "v1.3.0", "v2.0.0-rc.1", "latest", "dev"} { //nolint:goconst // readable fixtures
		digests[tag] = push(t, src.repo, tag, image(t))
	}
	digests["v1.2.0"] = push(t, src.repo, "v1.2.0", idx)
	idxDesc := must(partial.Descriptor(idx))
	referrer := pushReferrer(t, src.repo, *idxDesc)
	sig := fallbackTag(digests["v1.3.0"]) + ".sig"
	sigDigest := push(t, src.repo, sig, image(t))

	req := Request{
		Source: src.repo, Target: dst.repo,
		Policy: tags.Policy{KeepLatest: 3},
	}
	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run: %v (%+v)", err, res)
	}
	want := []string{"v1.1.0", "v1.2.0", "v1.3.0"} //nolint:goconst // readable fixtures
	if got := tagsOf(res.Copied); !slices.Equal(got, want) {
		t.Fatalf("copied %v, want %v (%+v)", got, want, res)
	}
	for _, a := range res.Copied {
		if a.Finished.IsZero() || a.UpstreamDigest != "" {
			t.Fatalf("%+v: want a finish time and no upstream digest", a)
		}
	}
	if !slices.Equal(res.Selected, []string{"v1.3.0", "v1.2.0", "v1.1.0"}) {
		t.Fatalf("selected %v, want newest first", res.Selected)
	}
	if got := list(t, dst.repo); !slices.Equal(got, append([]string{sig}, want...)) {
		t.Fatalf("target tags %v", got)
	}
	for _, a := range res.Copied {
		if a.Digest != digests[a.Tag].String() {
			t.Fatalf("%s: result digest %s, want %s", a.Tag, a.Digest, digests[a.Tag])
		}
		if got, _ := headDigest(t, dst.repo.Tag(a.Tag)); got != a.Digest {
			t.Fatalf("%s: target digest %s, want %s", a.Tag, got, a.Digest)
		}
		wantRefs := map[string]int{"v1.2.0": 1, "v1.3.0": 1}[a.Tag]
		if a.Referrers != wantRefs {
			t.Fatalf("%s: %d referrers, want %d", a.Tag, a.Referrers, wantRefs)
		}
	}
	if _, ok := headDigest(t, dst.repo.Digest(referrer.String())); !ok {
		t.Fatal("referrer not copied")
	}
	if got, _ := headDigest(t, dst.repo.Tag(sig)); got != sigDigest.String() {
		t.Fatalf("legacy signature tag digest %s, want %s", got, sigDigest)
	}

	writes := dst.writes.Load()
	res, err = Run(context.Background(), req)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := tagsOf(res.Skipped); !slices.Equal(got, want) || len(res.Copied) != 0 {
		t.Fatalf("second run: %+v", res)
	}
	if n := dst.writes.Load() - writes; n != 0 {
		t.Fatalf("second run wrote %d requests", n)
	}
}

// Signatures published after a tag was mirrored still reach the target,
// without copying the image again.
func TestRunSyncsReferrersOfUpToDateTags(t *testing.T) {
	src := newRegistry(t, regOpts{referrers: true})
	dst := newRegistry(t, regOpts{referrers: true})
	img := image(t)
	d := push(t, src.repo, v100, img)
	req := Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}}
	if _, err := Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	referrer := pushReferrer(t, src.repo, *must(partial.Descriptor(img)))
	sig := fallbackTag(d) + ".sig"
	sigDigest := push(t, src.repo, sig, image(t))
	before := len(dst.manifestPuts())

	res, err := Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run: %v (%+v)", err, res)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Referrers != 2 || len(res.Copied) != 0 {
		t.Fatalf("result %+v", res)
	}
	if _, ok := headDigest(t, dst.repo.Digest(referrer.String())); !ok {
		t.Fatal("new referrer not copied")
	}
	if got, _ := headDigest(t, dst.repo.Tag(sig)); got != sigDigest.String() {
		t.Fatalf("signature tag digest %s, want %s", got, sigDigest)
	}
	for _, p := range dst.manifestPuts()[before:] {
		if strings.HasSuffix(p, "/"+v100) || strings.HasSuffix(p, "/"+d.String()) {
			t.Fatalf("image re-copied: PUT %s", p)
		}
	}

	writes, gets := dst.writes.Load(), src.manifestGets.Load()
	res, err = Run(context.Background(), req)
	if err != nil || len(res.Skipped) != 1 || res.Skipped[0].Referrers != 2 {
		t.Fatalf("third run: %v %+v", err, res)
	}
	if n := dst.writes.Load() - writes; n != 0 {
		t.Fatalf("third run wrote %d requests", n)
	}
	// Some registries count manifest GETs as pulls.
	if n := src.manifestGets.Load() - gets; n != 0 {
		t.Fatalf("third run made %d source manifest GETs", n)
	}
}

func TestRunTagMutation(t *testing.T) {
	cases := []struct {
		policy                  v1alpha1.OnTagMutation
		copied, skipped, mutate bool
		wantErr                 error
	}{
		{v1alpha1.OnTagMutationFail, false, false, true, ErrTagMutated},
		{"", false, false, true, ErrTagMutated},
		{v1alpha1.OnTagMutationOverwrite, true, false, true, nil},
		{v1alpha1.OnTagMutationIgnore, false, true, false, nil},
	}
	for _, tc := range cases {
		t.Run(string(tc.policy), func(t *testing.T) {
			src := newRegistry(t, regOpts{})
			dst := newRegistry(t, regOpts{})
			upstream := push(t, src.repo, v100, image(t))
			push(t, src.repo, "v1.1.0", image(t))
			old := push(t, dst.repo, v100, image(t))

			res, err := Run(context.Background(), Request{
				Source: src.repo, Target: dst.repo,
				Policy:        tags.Policy{Include: []string{"."}},
				OnTagMutation: tc.policy,
			})
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			has := func(as []Artifact) bool { return slices.Contains(tagsOf(as), v100) }
			if has(res.Copied) != tc.copied || has(res.Skipped) != tc.skipped || has(res.Mutated) != tc.mutate {
				t.Fatalf("result %+v", res)
			}
			if !slices.Contains(tagsOf(res.Copied), "v1.1.0") {
				t.Fatalf("other tags must still sync: %+v", res)
			}
			want := old
			if tc.copied {
				want = upstream
			}
			if got, _ := headDigest(t, dst.repo.Tag(v100)); got != want.String() {
				t.Fatalf("target digest %s, want %s", got, want)
			}
			// An ignored mutation reports what the target holds.
			for _, a := range res.Skipped {
				if a.Tag == v100 && (a.Digest != old.String() || a.UpstreamDigest != upstream.String()) {
					t.Fatalf("skipped %+v, want target digest %s and upstream %s", a, old, upstream)
				}
			}
		})
	}
}

// A failed overwrite is only reported as Failed, not as Mutated.
func TestRunFailedOverwrite(t *testing.T) {
	src := newRegistry(t, regOpts{})
	dst := newRegistry(t, regOpts{})
	push(t, src.repo, v100, index(t, "linux/amd64"))
	old := push(t, dst.repo, v100, image(t))

	res, err := Run(context.Background(), Request{
		Source: src.repo, Target: dst.repo,
		Policy:            tags.Policy{Tags: []string{v100}},
		OnTagMutation:     v1alpha1.OnTagMutationOverwrite,
		RequiredPlatforms: []string{"linux/s390x"},
	})
	if err == nil || len(res.Mutated) != 0 || !slices.Equal(tagsOf(res.Failed), []string{v100}) || res.Failed[0].Finished.IsZero() {
		t.Fatalf("err %v, result %+v", err, res)
	}
	if got, _ := headDigest(t, dst.repo.Tag(v100)); got != old.String() {
		t.Fatalf("target digest %s, want %s", got, old)
	}
}

func TestRunMaxTags(t *testing.T) {
	src := newRegistry(t, regOpts{})
	dst := newRegistry(t, regOpts{})
	for i := range 3 {
		push(t, src.repo, fmt.Sprintf("v1.0.%d", i), image(t))
	}
	_, err := Run(context.Background(), Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{KeepLatest: 1}, MaxTags: 2})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want tag limit error, got %v", err)
	}
	if n := dst.writes.Load(); n != 0 {
		t.Fatalf("target written %d times", n)
	}
}

// ghcr.io has no referrers API, so ggcr reads the sha256-<hex> fallback tag.
// That tag may point to an unrelated index whose children have no subject.
func TestRunIgnoresFallbackTagPollution(t *testing.T) {
	src := newRegistry(t, regOpts{})
	dst := newRegistry(t, regOpts{referrers: true})
	d := push(t, src.repo, v100, image(t))
	pollution := index(t, "linux/amd64", "linux/arm64")
	push(t, src.repo, fallbackTag(d), pollution)

	res, err := Run(context.Background(), Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Copied) != 1 || res.Copied[0].Referrers != 0 {
		t.Fatalf("result %+v", res)
	}
	children := must(pollution.IndexManifest())
	for _, c := range children.Manifests {
		if _, ok := headDigest(t, dst.repo.Digest(c.Digest.String())); ok {
			t.Fatalf("fallback child %s copied as referrer", c.Digest)
		}
	}
}

func TestRunMissingPlatform(t *testing.T) {
	src := newRegistry(t, regOpts{})
	dst := newRegistry(t, regOpts{})
	push(t, src.repo, v100, index(t, "linux/amd64", "linux/arm64/v8"))
	push(t, src.repo, "v1.1.0", index(t, "linux/amd64", "linux/s390x"))
	push(t, src.repo, "v1.2.0", index(t, "linux/amd64", "linux/arm64"))

	res, err := Run(context.Background(), Request{
		Source: src.repo, Target: dst.repo,
		Policy:            tags.Policy{Include: []string{"."}},
		RequiredPlatforms: []string{"linux/arm64/v8", "linux/amd64"},
	})
	if err == nil {
		t.Fatal("want error for failed tags")
	}
	// arm64 and arm64/v8 are the same platform, either way round.
	if !slices.Equal(tagsOf(res.Copied), []string{v100, "v1.2.0"}) || !slices.Equal(tagsOf(res.Failed), []string{"v1.1.0"}) {
		t.Fatalf("result %+v", res)
	}
	if _, ok := headDigest(t, dst.repo.Tag("v1.1.0")); ok {
		t.Fatal("tag with missing platform was written")
	}
}

func TestRunNeverLeaksCredentials(t *testing.T) {
	src := newRegistry(t, regOpts{referrers: true, auth: true})
	dst := newRegistry(t, regOpts{})
	auth := remote.WithAuth(&authn.Basic{Username: user, Password: password})
	push(t, src.repo, v100, image(t), auth)

	for _, pass := range []string{password, "wrong-" + password} {
		res, err := Run(context.Background(), Request{
			Source: src.repo, Target: dst.repo,
			Policy:     tags.Policy{Tags: []string{v100}},
			SourceOpts: []remote.Option{remote.WithAuth(&authn.Basic{Username: user, Password: pass})},
		})
		out := fmt.Sprintf("%+v %v", res, err)
		if strings.Contains(out, password) {
			t.Fatalf("password leaked: %s", out)
		}
		if pass == password && (err != nil || len(res.Copied) != 1) {
			t.Fatalf("with valid credentials: %s", out)
		}
		if pass != password && err == nil {
			t.Fatal("want error with wrong credentials")
		}
	}
}

// Some registries omit Docker-Content-Digest on HEAD. Resolution then falls
// back to GET, for both source and target.
func TestRunWithoutHeadDigest(t *testing.T) {
	src := newRegistry(t, regOpts{noHeadDigest: true})
	dst := newRegistry(t, regOpts{noHeadDigest: true})
	d := push(t, src.repo, v100, image(t))
	req := Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}}

	for _, wantSkipped := range []bool{false, true} {
		res, err := Run(context.Background(), req)
		if err != nil {
			t.Fatalf("Run: %v (%+v)", err, res)
		}
		got := res.Copied
		if wantSkipped {
			got = res.Skipped
		}
		if len(got) != 1 || got[0].Digest != d.String() {
			t.Fatalf("skipped=%v: %+v", wantSkipped, res)
		}
	}
}

// A rate-limited HEAD is returned as is, never retried as a counted GET.
func TestRunHeadRateLimitedNoGet(t *testing.T) {
	src := newRegistry(t, regOpts{})
	dst := newRegistry(t, regOpts{})
	push(t, src.repo, v100, image(t))
	src.headStatus.Store(http.StatusTooManyRequests)
	gets := src.manifestGets.Load()

	res, err := Run(context.Background(), Request{
		Source: src.repo, Target: dst.repo,
		Policy:     tags.Policy{Tags: []string{v100}},
		SourceOpts: []remote.Option{remote.WithRetryBackoff(remote.Backoff{Steps: 1})},
	})
	if err == nil || !slices.Equal(tagsOf(res.Failed), []string{v100}) {
		t.Fatalf("err %v, result %+v", err, res)
	}
	if n := src.manifestGets.Load() - gets; n != 0 {
		t.Fatalf("%d manifest GETs after a 429 HEAD", n)
	}
}

func TestRunContextCancelled(t *testing.T) {
	src := newRegistry(t, regOpts{})
	dst := newRegistry(t, regOpts{})
	push(t, src.repo, v100, image(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, Request{Source: src.repo, Target: dst.repo, Policy: tags.Policy{Tags: []string{v100}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := dst.writes.Load(); n != 0 {
		t.Fatalf("target written %d times", n)
	}
}

func TestShortKeepsRunes(t *testing.T) {
	msg := short(errors.New("a" + strings.Repeat("\u017c", maxMessage)))
	if !utf8.ValidString(msg) || !strings.HasSuffix(msg, "...") || len(msg) > maxMessage+3 {
		t.Fatalf("bad truncation: %q", msg)
	}
}

// artifactSize is the config and layer bytes of an image.
func artifactSize(t *testing.T, img v1.Image) int64 {
	t.Helper()
	m := must(img.Manifest())
	n := m.Config.Size
	for _, l := range m.Layers {
		n += l.Size
	}
	return n
}

func TestRunRefusesArtifactsOverMaxSize(t *testing.T) {
	src := newRegistry(t, regOpts{referrers: true})
	dst := newRegistry(t, regOpts{referrers: true})
	small, big := image(t), must(random.Image(4096, 2))
	idx := index(t, "linux/amd64", "linux/arm64")
	push(t, src.repo, "small", small)
	bigDigest := push(t, src.repo, "big", big)
	idxDigest := push(t, src.repo, "idx", idx)
	// A referrer does not count toward the size of its subject.
	pushReferrer(t, src.repo, *must(partial.Descriptor(small)))

	limit := artifactSize(t, small)
	children := must(idx.IndexManifest()).Manifests
	var idxSize int64
	for _, c := range children {
		n := artifactSize(t, must(idx.Image(c.Digest)))
		limit = max(limit, n)
		idxSize += n
	}

	res, err := Run(context.Background(), Request{
		Source: src.repo, Target: dst.repo,
		Policy:          tags.Policy{Tags: []string{"small", "big", "idx"}},
		MaxArtifactSize: limit,
	})
	if err == nil {
		t.Fatal("want an error for the refused tags")
	}
	if got := tagsOf(res.Copied); !slices.Equal(got, []string{"small"}) || res.Copied[0].Referrers != 1 {
		t.Fatalf("copied %+v", res.Copied)
	}
	if got := tagsOf(res.Failed); !slices.Equal(got, []string{"big", "idx"}) {
		t.Fatalf("failed %v", got)
	}
	for _, e := range []string{
		fmt.Sprintf("big: artifact too large: %d > %d", artifactSize(t, big), limit),
		fmt.Sprintf("idx: artifact too large: %d > %d", idxSize, limit),
	} {
		if !slices.Contains(res.Errors, e) {
			t.Fatalf("errors %q, want %q", res.Errors, e)
		}
	}
	for _, d := range []v1.Hash{bigDigest, idxDigest, children[0].Digest} {
		if _, ok := headDigest(t, dst.repo.Digest(d.String())); ok {
			t.Fatalf("%s copied", d)
		}
	}
	for _, l := range must(big.Layers()) {
		u := fmt.Sprintf("http://%s/v2/%s/blobs/%s", dst.repo.RegistryStr(), dst.repo.RepositoryStr(), must(l.Digest()))
		resp := must(http.Head(u)) //nolint:gosec,noctx // in-process registry
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("layer of the refused image: HEAD %d", resp.StatusCode)
		}
	}
}
