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

// Package sync copies selected tags from a source repository to a target
// repository by digest, with their referrers and cosign tag-scheme artifacts.
package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

// ErrArtifactTooLarge means the config and layers of an artifact add up to
// more than Request.MaxArtifactSize.
var ErrArtifactTooLarge = errors.New("artifact too large")

// ErrTagMutated means a target tag points to a different digest than the
// upstream tag and the mutation policy is Fail.
var ErrTagMutated = errors.New("sync: target tag points to a different digest than upstream")

const (
	maxMessage = 300
	// maxPages stops a registry that keeps returning empty tag pages.
	maxPages = 1000
)

// Request describes one sync of a source repository to a target repository.
type Request struct {
	Source, Target name.Repository
	Policy         tags.Policy
	// RequiredPlatforms must all exist in the source, as os/arch[/variant].
	// Empty skips the check.
	RequiredPlatforms []string
	// OnTagMutation defaults to Fail.
	OnTagMutation          v1alpha1.OnTagMutation
	SourceOpts, TargetOpts []remote.Option
	// MaxTags caps the upstream listing. Zero means tags.MaxTags.
	MaxTags int
	// MaxArtifactSize caps the config and layer bytes of one artifact,
	// summed over every manifest of an index, and separately the bytes of
	// the referrers copied for it. Zero means no limit.
	MaxArtifactSize int64
	// Gate scans tags before they are copied. Nil copies without a scan.
	Gate *Gate
	// DeleteTag deletes a target tag from one digest. Nil uses the OCI
	// distribution tag delete. synccmd sets it for registries that refuse
	// that, such as Harbor; it returns registry.ErrTagNotFound when the
	// registry answers that the tag is not there.
	DeleteTag func(ctx context.Context, tag, digest string) error
	// Prunable lists the target tags Run may delete once the selection no
	// longer includes them, with the digest each must still have. Empty
	// prunes nothing; Rescan ignores it.
	Prunable []Artifact
}

// Artifact is one tag and the digest it resolved to. For a mutated tag
// skipped under the Ignore policy, Digest is the digest the target keeps
// and UpstreamDigest the one it ignored.
type Artifact struct {
	Tag, Digest    string
	UpstreamDigest string
	// Finished is when the processing of the tag ended.
	Finished time.Time
	// Referrers counts the referrers and cosign tag-scheme artifacts of the
	// digest that the target holds after the run.
	Referrers int
	// Scan is the gate outcome; nil when the tag was not scanned.
	Scan *Scan
	// SkippedReferrers lists the digests of referrers and cosign tag-scheme
	// artifacts the gate did not copy because they are not only
	// signatures, attestations or SBOMs.
	SkippedReferrers []string
	// Untag is what a re-scan did with a tag with findings.
	Untag v1alpha1.VulnerableTagAction
}

// Result lists what happened to each selected tag. Overwritten mutated tags
// are in both Mutated and Copied. An up-to-date tag is reported Failed when
// its referrers cannot be listed or copied; the image itself is untouched. A tag deleted upstream is not selected, so
// its target tag stays untouched unless it is in Request.Prunable.
type Result struct {
	// Selected lists the selected tags in the order tags.Select returns
	// them, newest version first.
	Selected []string
	// Stats counts what the selection did; Run sets it, Rescan does not.
	Stats                            *tags.Stats
	Copied, Skipped, Mutated, Failed []Artifact
	// Blocked lists the tags the gate did not copy.
	Blocked []Artifact
	// Untagged lists the tags a re-scan deleted from the target.
	Untagged []Artifact
	// Pruned lists the Prunable tags Run deleted from the target.
	Pruned []Artifact
	// Dropped lists the Prunable tags Run found gone from the target or
	// pointing at another digest, and left alone.
	Dropped []Artifact
	Errors  []string
	// Gate is the scanner check of a gated run, syncspec.GateOK or a scan
	// error reason; empty when nothing was scanned.
	Gate string
	// JavaScanned means the Java DB was used, so JAR files were scanned.
	JavaScanned bool
}

type syncer struct {
	req       Request
	platforms []v1.Platform
	src, dst  *remote.Puller
	pusher    *remote.Pusher
	gate      *gateState
	// listed is the source tag listing of the run; nil when the policy
	// lists only explicit tags.
	listed []string
}

// Run lists the source tags, selects them with r.Policy and copies each one
// by digest. A failed tag does not stop the others. Target tags whose
// upstream tag was deleted are left as they are. The error is non-nil
// when the listing fails, a tag fails or a mutated tag is refused.
func Run(ctx context.Context, r Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	s, err := newSyncer(r)
	if err != nil {
		return Result{}, err
	}
	selected, st, err := s.selectTags(ctx)
	if err != nil {
		return Result{}, err
	}

	res := Result{Selected: selected, Stats: &st}
	var mutated bool
	for _, tag := range selected {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		err := s.tag(ctx, tag, &res)
		switch {
		case err == nil:
		case errors.Is(err, ErrTagMutated):
			mutated = true
			res.Errors = append(res.Errors, tag+": "+err.Error())
		default:
			res.Failed = append(res.Failed, Artifact{Tag: tag})
			res.Errors = append(res.Errors, tag+": "+short(err))
		}
		stamp(&res, tag, time.Now())
	}
	if s.gate != nil {
		res.Gate, res.JavaScanned = s.gate.reason, s.gate.javaScanned
		if s.gate.root != nil {
			_ = s.gate.root.Close()
		}
	}
	s.prune(ctx, &res, mutated)
	var errs []error
	if err := blockedError(&res, res.Blocked); err != nil {
		errs = append(errs, err)
	}
	if mutated {
		errs = append(errs, ErrTagMutated)
	}
	if len(res.Failed) > 0 {
		errs = append(errs, fmt.Errorf("sync: %d of %d tags failed", len(res.Failed), len(selected)))
	}
	return res, errors.Join(errs...)
}

// stamp sets the finish time of tag in every list. A tag is processed
// once, so its entries are the last ones appended.
func stamp(res *Result, tag string, t time.Time) {
	for _, as := range [][]Artifact{res.Copied, res.Skipped, res.Mutated, res.Failed, res.Blocked, res.Untagged} {
		if n := len(as); n > 0 && as[n-1].Tag == tag {
			as[n-1].Finished = t
		}
	}
}

func newSyncer(r Request) (*syncer, error) {
	if r.MaxTags <= 0 {
		r.MaxTags = tags.MaxTags
	}
	switch r.OnTagMutation {
	case "":
		r.OnTagMutation = v1alpha1.OnTagMutationFail
	case v1alpha1.OnTagMutationFail, v1alpha1.OnTagMutationOverwrite, v1alpha1.OnTagMutationIgnore:
	default:
		return nil, fmt.Errorf("sync: unknown onTagMutation %q", r.OnTagMutation)
	}
	s := &syncer{req: r}
	if r.Gate != nil {
		s.gate = &gateState{Gate: *r.Gate}
	}
	for _, p := range r.RequiredPlatforms {
		pl, err := v1.ParsePlatform(p)
		if err != nil {
			return nil, fmt.Errorf("sync: platform %q: %w", p, err)
		}
		s.platforms = append(s.platforms, normalize(*pl))
	}
	var err error
	// ggcr already retries 408, 429 and 5xx; do not add another retry layer.
	if s.src, err = remote.NewPuller(r.SourceOpts...); err != nil {
		return nil, err
	}
	if s.dst, err = remote.NewPuller(r.TargetOpts...); err != nil {
		return nil, err
	}
	if s.pusher, err = remote.NewPusher(r.TargetOpts...); err != nil {
		return nil, err
	}
	return s, nil
}

// deleteTag deletes tag, which the caller resolved to digest, from the
// target.
func (s *syncer) deleteTag(ctx context.Context, tag, digest string) error {
	if s.req.DeleteTag != nil {
		return s.req.DeleteTag(ctx, tag, digest)
	}
	return s.pusher.Delete(ctx, s.req.Target.Tag(tag))
}

// selectTags picks the tags to sync. A policy with only explicit tags
// resolves each one directly and never lists the source, so the listing
// limit cannot apply. A tag the source does not have is dropped, as when
// selecting from a listing.
func (s *syncer) selectTags(ctx context.Context) ([]string, tags.Stats, error) {
	p := s.req.Policy
	if len(p.Include) > 0 || p.SemverRange != "" || p.KeepLatest > 0 {
		all, err := s.list(ctx)
		if err != nil {
			return nil, tags.Stats{}, err
		}
		s.listed = all
		return tags.Explain(all, p)
	}
	selected, st, err := tags.Explain(p.Tags, p)
	if err != nil {
		return nil, st, err
	}
	// Nothing was listed: the explicit tags are the input.
	st = tags.Stats{}
	selected = slices.DeleteFunc(selected, func(t string) bool {
		_, err := resolve(ctx, s.src, s.req.Source.Tag(t))
		if notFound(err) {
			st.Missing = append(st.Missing, t)
			return true
		}
		return false
	})
	st.Selected = len(selected)
	return selected, st, nil
}

// list pages through the source tags and stops with an error past MaxTags,
// so selection never runs on a truncated list (threat model T22).
func (s *syncer) list(ctx context.Context) ([]string, error) {
	l, err := s.src.Lister(ctx, s.req.Source)
	if err != nil {
		return nil, fmt.Errorf("sync: list source tags: %w", err)
	}
	var all []string
	for pages := 0; l.HasNext(); pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf("sync: source tag list exceeds %d pages", maxPages)
		}
		page, err := l.Next(ctx)
		if err != nil {
			return nil, fmt.Errorf("sync: list source tags: %w", err)
		}
		all = append(all, page.Tags...)
		if len(all) > s.req.MaxTags {
			return nil, fmt.Errorf("sync: source has more than %d tags, the limit (maxListedTags of the ClusterMirrorTarget)", s.req.MaxTags)
		}
	}
	return all, nil
}

// tag syncs one tag. It resolves the source tag once and then works only by
// digest. The target tag moves last, after the digest and its referrers are
// copied, so a partial copy is retried on the next run.
func (s *syncer) tag(ctx context.Context, tag string, res *Result) error {
	src, err := resolve(ctx, s.src, s.req.Source.Tag(tag))
	if err != nil {
		return fmt.Errorf("resolve source tag: %w", err)
	}
	a := Artifact{Tag: tag, Digest: src.Digest.String()}
	overwrite := false

	dst, err := resolve(ctx, s.dst, s.req.Target.Tag(tag))
	switch {
	case notFound(err):
	case err != nil:
		return fmt.Errorf("check target tag: %w", err)
	case dst.Digest == src.Digest:
		if s.gate != nil && s.gate.Judged[tag] != a.Digest {
			if a.Scan, err = s.scanPresent(ctx, s.src, s.req.Source, a.Digest); err != nil {
				return err
			}
		}
		// A blocked tag gets nothing more, also when it is already there.
		if a.Scan == nil || !a.Scan.Block {
			if a.Referrers, err = s.referrers(ctx, src.Digest, &a.SkippedReferrers); err != nil {
				return err
			}
		}
		res.Skipped = append(res.Skipped, a)
		return nil
	case s.req.OnTagMutation == v1alpha1.OnTagMutationIgnore:
		// Report what the target holds, not the upstream digest.
		a.Digest, a.UpstreamDigest = dst.Digest.String(), a.Digest
		// The target digest is what nodes pull, so the gate judges it.
		if s.gate != nil && s.gate.Judged[tag] != a.Digest {
			if a.Scan, err = s.scanPresent(ctx, s.dst, s.req.Target, a.Digest); err != nil {
				return err
			}
		}
		res.Skipped = append(res.Skipped, a)
		return nil
	case s.req.OnTagMutation == v1alpha1.OnTagMutationOverwrite:
		overwrite = true
	default:
		res.Mutated = append(res.Mutated, a)
		return fmt.Errorf("%w: target %s, upstream %s", ErrTagMutated, dst.Digest, src.Digest)
	}

	desc, err := s.src.Get(ctx, s.req.Source.Digest(a.Digest))
	if err != nil {
		return fmt.Errorf("fetch source manifest: %w", err)
	}
	if err := s.checkPlatforms(desc); err != nil {
		return err
	}
	if err := s.checkSize(ctx, s.src, s.req.Source, desc); err != nil {
		return err
	}
	var from remote.Taggable = desc
	if s.gate != nil {
		defer func() { _ = os.RemoveAll(s.gate.LayoutDir) }()
		if a.Scan, from, err = s.scan(ctx, desc, false); err != nil {
			return err
		}
		if a.Scan.Block {
			res.Blocked = append(res.Blocked, a)
			return nil
		}
	}
	if err := s.push(ctx, desc.Digest, from); err != nil {
		return err
	}
	if a.Referrers, err = s.referrers(ctx, desc.Digest, &a.SkippedReferrers); err != nil {
		return err
	}
	if err := s.pusher.Put(ctx, s.req.Target.Tag(tag), desc); err != nil {
		return fmt.Errorf("tag target: %w", err)
	}
	if overwrite {
		res.Mutated = append(res.Mutated, a)
	}
	res.Copied = append(res.Copied, a)
	return nil
}

// checkPlatforms verifies that every requested platform is in the source.
// Phase 1 always copies the whole index: dropping children would change the
// index digest and break digest-first mirroring and signatures on the index.
func (s *syncer) checkPlatforms(desc *remote.Descriptor) error {
	if len(s.platforms) == 0 {
		return nil
	}
	var have []v1.Platform
	if desc.MediaType.IsIndex() {
		im, err := v1.ParseIndexManifest(bytes.NewReader(desc.Manifest))
		if err != nil {
			return err
		}
		for _, m := range im.Manifests {
			if m.Platform != nil {
				have = append(have, normalize(*m.Platform))
			}
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			return err
		}
		cf, err := img.ConfigFile()
		if err != nil {
			return err
		}
		if p := cf.Platform(); p != nil {
			have = append(have, normalize(*p))
		}
	}
	for _, want := range s.platforms {
		if !slices.ContainsFunc(have, func(h v1.Platform) bool { return h.Satisfies(want) }) {
			return fmt.Errorf("platform %s not in source", want)
		}
	}
	return nil
}

// checkSize refuses an artifact larger than MaxArtifactSize before anything
// of it is copied (threat model T10).
func (s *syncer) checkSize(ctx context.Context, p *remote.Puller, repo name.Repository, desc *remote.Descriptor) error {
	if s.req.MaxArtifactSize <= 0 {
		return nil
	}
	n, err := s.size(ctx, p, repo, desc)
	if err != nil {
		return err
	}
	if n > s.req.MaxArtifactSize {
		return fmt.Errorf("%w: %d > %d", ErrArtifactTooLarge, n, s.req.MaxArtifactSize)
	}
	return nil
}

// checkReferrerSize adds the size of a referrer about to be copied to
// used and refuses it when the referrers copied for one artifact in this
// run would exceed MaxArtifactSize. Referrers have their own budget, so a
// large signature or SBOM does not count against the image.
func (s *syncer) checkReferrerSize(ctx context.Context, desc *remote.Descriptor, used *int64) error {
	if s.req.MaxArtifactSize <= 0 {
		return nil
	}
	n, err := s.size(ctx, s.src, s.req.Source, desc)
	if err != nil {
		return err
	}
	*used = min(*used, math.MaxInt64-n) + n
	if *used > s.req.MaxArtifactSize {
		return fmt.Errorf("%w: referrers %d > %d", ErrArtifactTooLarge, *used, s.req.MaxArtifactSize)
	}
	return nil
}

// size sums the config and layer sizes of a manifest, or of every manifest
// of an index, as the manifests declare them. ggcr checks each blob
// against its declared size when it copies it. The sum saturates instead
// of overflowing.
func (s *syncer) size(ctx context.Context, p *remote.Puller, repo name.Repository, desc *remote.Descriptor) (int64, error) {
	var total int64
	add := func(n int64) error {
		if n < 0 {
			return fmt.Errorf("%s declares a negative size", desc.Digest)
		}
		total = min(total, math.MaxInt64-n) + n
		return nil
	}
	if desc.MediaType.IsIndex() {
		im, err := v1.ParseIndexManifest(bytes.NewReader(desc.Manifest))
		if err != nil {
			return 0, err
		}
		for _, m := range im.Manifests {
			child, err := p.Get(ctx, repo.Digest(m.Digest.String()))
			if err != nil {
				return 0, fmt.Errorf("fetch manifest %s: %w", m.Digest, err)
			}
			n, err := s.size(ctx, p, repo, child)
			if err != nil {
				return 0, err
			}
			if err := add(n); err != nil {
				return 0, err
			}
		}
		return total, nil
	}
	m, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return 0, err
	}
	if err := add(m.Config.Size); err != nil {
		return 0, err
	}
	for _, l := range m.Layers {
		if err := add(l.Size); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// normalize treats arm64 and arm64/v8 as the same platform, like containerd.
func normalize(p v1.Platform) v1.Platform {
	if p.Architecture == "arm64" && (p.Variant == "v8" || p.Variant == "8") {
		p.Variant = ""
	}
	return p
}

// copy writes desc to the target by digest.
func (s *syncer) copy(ctx context.Context, desc *remote.Descriptor) error {
	return s.push(ctx, desc.Digest, desc)
}

// push writes t to the target as digest d. ggcr keeps the original manifest
// bytes, and the target digest is checked afterwards.
func (s *syncer) push(ctx context.Context, d v1.Hash, t remote.Taggable) error {
	ref := s.req.Target.Digest(d.String())
	if err := s.pusher.Push(ctx, ref, t); err != nil {
		return fmt.Errorf("copy %s: %w", d, err)
	}
	// ggcr rejects a response for a digest reference whose digest differs,
	// so a successful resolve proves the target holds the same digest.
	if _, err := resolve(ctx, s.dst, ref); err != nil {
		return fmt.Errorf("verify %s: %w", d, err)
	}
	return nil
}

// referrers copies the OCI referrers of d and the cosign tag-scheme
// artifacts sha256-<hex>.sig, .att and .sbom that the target lacks. It
// returns how many the target holds afterwards.
func (s *syncer) referrers(ctx context.Context, d v1.Hash, skipped *[]string) (int, error) {
	opts := append(slices.Clone(s.req.SourceOpts), remote.Reuse(s.src), remote.WithContext(ctx))
	idx, err := remote.Referrers(s.req.Source.Digest(d.String()), opts...)
	if err != nil {
		return 0, fmt.Errorf("list referrers: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return 0, fmt.Errorf("list referrers: %w", err)
	}
	n := 0
	var budget int64
	for _, m := range im.Manifests {
		// Check the target first: some registries count manifest GETs as pulls.
		_, err := resolve(ctx, s.dst, s.req.Target.Digest(m.Digest.String()))
		if err == nil {
			// Fallback-tag pollution has no artifactType; real referrers do.
			if m.ArtifactType != "" {
				n++
			}
			continue
		}
		if !notFound(err) {
			return n, fmt.Errorf("check target referrer %s: %w", m.Digest, err)
		}
		desc, err := s.src.Get(ctx, s.req.Source.Digest(m.Digest.String()))
		if err != nil {
			return n, fmt.Errorf("fetch referrer: %w", err)
		}
		// Without a referrers API ggcr reads the sha256-<hex> fallback tag,
		// which may point at unrelated manifests. Keep only real referrers.
		var mf struct{ Subject *v1.Descriptor }
		if err := json.Unmarshal(desc.Manifest, &mf); err != nil || mf.Subject == nil || mf.Subject.Digest != d {
			continue
		}
		if !s.ungatedArtifact(desc) {
			*skipped = append(*skipped, desc.Digest.String())
			continue
		}
		if err := s.checkReferrerSize(ctx, desc, &budget); err != nil {
			return n, err
		}
		if !s.jsonArtifact(desc) {
			*skipped = append(*skipped, desc.Digest.String())
			continue
		}
		if err := s.copy(ctx, desc); err != nil {
			return n, err
		}
		n++
	}
	for _, suffix := range []string{".sig", ".att", ".sbom"} {
		tag := d.Algorithm + "-" + d.Hex + suffix
		src, err := resolve(ctx, s.src, s.req.Source.Tag(tag))
		if notFound(err) {
			continue
		}
		if err != nil {
			return n, fmt.Errorf("resolve %s: %w", tag, err)
		}
		dst, err := resolve(ctx, s.dst, s.req.Target.Tag(tag))
		if err == nil && dst.Digest == src.Digest {
			n++
			continue
		}
		if err != nil && !notFound(err) {
			return n, fmt.Errorf("check target %s: %w", tag, err)
		}
		desc, err := s.src.Get(ctx, s.req.Source.Digest(src.Digest.String()))
		if err != nil {
			return n, fmt.Errorf("fetch %s: %w", tag, err)
		}
		if !s.ungatedArtifact(desc) {
			*skipped = append(*skipped, desc.Digest.String())
			continue
		}
		if err := s.checkReferrerSize(ctx, desc, &budget); err != nil {
			return n, err
		}
		if !s.jsonArtifact(desc) {
			*skipped = append(*skipped, desc.Digest.String())
			continue
		}
		if err := s.ensure(ctx, desc); err != nil {
			return n, err
		}
		if err := s.pusher.Put(ctx, s.req.Target.Tag(tag), desc); err != nil {
			return n, fmt.Errorf("tag %s: %w", tag, err)
		}
		n++
	}
	return n, nil
}

// ensure copies desc to the target unless its digest is already there.
func (s *syncer) ensure(ctx context.Context, desc *remote.Descriptor) error {
	_, err := resolve(ctx, s.dst, s.req.Target.Digest(desc.Digest.String()))
	if err == nil {
		return nil
	}
	if !notFound(err) {
		return fmt.Errorf("check target %s: %w", desc.Digest, err)
	}
	return s.copy(ctx, desc)
}

// resolve returns the descriptor of ref. Like crane digest, it falls back to
// GET when HEAD fails without a registry error, for registries that omit
// Docker-Content-Digest on HEAD. Registry errors such as 401, 404 or 429 are
// returned as is, so a free HEAD never turns into a counted GET.
func resolve(ctx context.Context, p *remote.Puller, ref name.Reference) (*v1.Descriptor, error) {
	d, err := p.Head(ctx, ref)
	var terr *transport.Error
	if err == nil || errors.As(err, &terr) {
		return d, err
	}
	desc, err := p.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &desc.Descriptor, nil
}

func notFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}

// short keeps result messages small. Registry references never carry
// userinfo and credentials travel only in headers, so errors hold none.
func short(err error) string {
	msg := err.Error()
	if len(msg) <= maxMessage {
		return msg
	}
	cut := maxMessage
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + "..."
}

// ungatedArtifact reports whether a referrer or cosign tag-scheme artifact
// may be copied: always without the gate; with it, only an image manifest
// whose layers are all signatures, attestations or SBOMs. Anything else,
// such as a runnable image tagged sha256-<hex>.sig, would bypass the scan.
func (s *syncer) ungatedArtifact(desc *remote.Descriptor) bool {
	if s.gate == nil {
		return true
	}
	if !desc.MediaType.IsImage() {
		return false
	}
	m, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	return err == nil && vuln.SupplyChainArtifact(layerTypes(m))
}

// jsonArtifact checks the content behind ungatedArtifact's labels: with the
// gate on, every layer must be JSON, read from the source after the size
// check bounded it.
func (s *syncer) jsonArtifact(desc *remote.Descriptor) bool {
	if s.gate == nil {
		return true
	}
	img, err := desc.Image()
	if err != nil {
		return false
	}
	m, err := img.Manifest()
	if err != nil {
		return false
	}
	return jsonLayers(m, func(h v1.Hash) (io.ReadCloser, error) {
		l, err := img.LayerByDigest(h)
		if err != nil {
			return nil, err
		}
		return l.Compressed()
	})
}

func layerTypes(m *v1.Manifest) []string {
	out := make([]string, 0, len(m.Layers))
	for _, l := range m.Layers {
		out = append(out, string(l.MediaType))
	}
	return out
}

// scanPresent scans a digest that is already on the target, read from p
// and repo, so that a mirror without a judged verdict still reports it.
// Nothing is pushed.
func (s *syncer) scanPresent(ctx context.Context, p *remote.Puller, repo name.Repository, digest string) (*Scan, error) {
	desc, err := p.Get(ctx, repo.Digest(digest))
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	if err := s.checkSize(ctx, p, repo, desc); err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(s.gate.LayoutDir) }()
	sc, _, err := s.scan(ctx, desc, true)
	return sc, err
}

// blockedError reports the tags of as that could not be judged, and lists
// them in res.Errors. Tags blocked for findings are the gate working and
// no error.
func blockedError(res *Result, as []Artifact) error {
	var reasons []string
	for _, a := range as {
		if a.Scan.Verdict != vuln.ScanError {
			continue
		}
		res.Errors = append(res.Errors, fmt.Sprintf("%s: scan error %s: %s", a.Tag, a.Scan.Reason, a.Scan.Detail))
		if !slices.Contains(reasons, a.Scan.Reason) {
			reasons = append(reasons, a.Scan.Reason)
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	return &ScanBlockedError{Reasons: reasons}
}
