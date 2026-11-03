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
	"net/http"
	"slices"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
)

// ErrTagMutated means a target tag points to a different digest than the
// upstream tag and the mutation policy is Fail.
var ErrTagMutated = errors.New("sync: target tag points to a different digest than upstream")

const maxMessage = 300

// Request describes one sync of a source repository to a target repository.
type Request struct {
	Source, Target name.Repository
	Policy         tags.Policy
	// Platforms must all exist in a source index, as os/arch[/variant].
	// Empty skips the check.
	Platforms []string
	// OnTagMutation defaults to Fail.
	OnTagMutation          v1alpha1.OnTagMutation
	SourceOpts, TargetOpts []remote.Option
	// MaxTags caps the upstream listing. Zero means tags.MaxTags.
	MaxTags int
}

// Artifact is one tag and the digest it resolved to.
type Artifact struct {
	Tag, Digest string
	// Referrers counts copied referrers and cosign tag-scheme artifacts.
	Referrers int
}

// Result lists what happened to each selected tag. Overwritten mutated tags
// are in both Mutated and Copied.
type Result struct {
	Copied, Skipped, Mutated, Failed []Artifact
	Errors                           []string
}

type syncer struct {
	req       Request
	platforms []v1.Platform
	src, dst  *remote.Puller
	push      *remote.Pusher
}

// Run lists the source tags, selects them with r.Policy and copies each one
// by digest. A failed tag does not stop the others. The error is non-nil
// when the listing fails, a tag fails or a mutated tag is refused.
func Run(ctx context.Context, r Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	s, err := newSyncer(r)
	if err != nil {
		return Result{}, err
	}
	all, err := s.list(ctx)
	if err != nil {
		return Result{}, err
	}
	selected, err := tags.Select(all, r.Policy)
	if err != nil {
		return Result{}, err
	}

	var res Result
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
	}
	var errs []error
	if mutated {
		errs = append(errs, ErrTagMutated)
	}
	if len(res.Failed) > 0 {
		errs = append(errs, fmt.Errorf("sync: %d of %d tags failed", len(res.Failed), len(selected)))
	}
	return res, errors.Join(errs...)
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
	for _, p := range r.Platforms {
		pl, err := v1.ParsePlatform(p)
		if err != nil {
			return nil, fmt.Errorf("sync: platform %q: %w", p, err)
		}
		s.platforms = append(s.platforms, *pl)
	}
	var err error
	if s.src, err = remote.NewPuller(r.SourceOpts...); err != nil {
		return nil, err
	}
	if s.dst, err = remote.NewPuller(r.TargetOpts...); err != nil {
		return nil, err
	}
	if s.push, err = remote.NewPusher(r.TargetOpts...); err != nil {
		return nil, err
	}
	return s, nil
}

// list pages through the source tags and stops with an error past MaxTags,
// so selection never runs on a truncated list (threat model T22).
func (s *syncer) list(ctx context.Context) ([]string, error) {
	l, err := s.src.Lister(ctx, s.req.Source)
	if err != nil {
		return nil, fmt.Errorf("sync: list source tags: %w", err)
	}
	var all []string
	// The page cap stops a registry that keeps returning empty pages.
	for pages := 0; l.HasNext(); pages++ {
		if pages > s.req.MaxTags {
			return nil, fmt.Errorf("sync: source tag list exceeds %d pages", s.req.MaxTags)
		}
		page, err := l.Next(ctx)
		if err != nil {
			return nil, fmt.Errorf("sync: list source tags: %w", err)
		}
		all = append(all, page.Tags...)
		if len(all) > s.req.MaxTags {
			return nil, fmt.Errorf("sync: source has more than %d tags, the limit", s.req.MaxTags)
		}
	}
	return all, nil
}

// tag syncs one tag. It resolves the source tag once and then works only by
// digest. The target tag moves last, after the digest and its referrers are
// copied, so a partial copy is retried on the next run.
func (s *syncer) tag(ctx context.Context, tag string, res *Result) error {
	src, err := s.src.Head(ctx, s.req.Source.Tag(tag))
	if err != nil {
		return fmt.Errorf("resolve source tag: %w", err)
	}
	a := Artifact{Tag: tag, Digest: src.Digest.String()}

	dst, err := s.dst.Head(ctx, s.req.Target.Tag(tag))
	switch {
	case notFound(err):
	case err != nil:
		return fmt.Errorf("check target tag: %w", err)
	case dst.Digest == src.Digest:
		res.Skipped = append(res.Skipped, a)
		return nil
	case s.req.OnTagMutation == v1alpha1.OnTagMutationIgnore:
		res.Skipped = append(res.Skipped, a)
		return nil
	case s.req.OnTagMutation == v1alpha1.OnTagMutationOverwrite:
		res.Mutated = append(res.Mutated, a)
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
	if err := s.copy(ctx, desc); err != nil {
		return err
	}
	if a.Referrers, err = s.referrers(ctx, desc.Digest); err != nil {
		return err
	}
	if err := s.push.Put(ctx, s.req.Target.Tag(tag), desc); err != nil {
		return fmt.Errorf("tag target: %w", err)
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
				have = append(have, *m.Platform)
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
			have = append(have, *p)
		}
	}
	for _, want := range s.platforms {
		if !slices.ContainsFunc(have, func(h v1.Platform) bool { return h.Satisfies(want) }) {
			return fmt.Errorf("platform %s not in source", want)
		}
	}
	return nil
}

// copy writes desc to the target by digest. ggcr keeps the original manifest
// bytes, and the target digest is checked afterwards.
func (s *syncer) copy(ctx context.Context, desc *remote.Descriptor) error {
	ref := s.req.Target.Digest(desc.Digest.String())
	if err := s.push.Push(ctx, ref, desc); err != nil {
		return fmt.Errorf("copy %s: %w", desc.Digest, err)
	}
	got, err := s.dst.Head(ctx, ref)
	if err != nil {
		return fmt.Errorf("verify %s: %w", desc.Digest, err)
	}
	if got.Digest != desc.Digest {
		return fmt.Errorf("target digest %s differs from source %s", got.Digest, desc.Digest)
	}
	return nil
}

// referrers copies the OCI referrers of d and the cosign tag-scheme
// artifacts sha256-<hex>.sig, .att and .sbom.
func (s *syncer) referrers(ctx context.Context, d v1.Hash) (int, error) {
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
	for _, m := range im.Manifests {
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
		if err := s.copy(ctx, desc); err != nil {
			return n, err
		}
		n++
	}
	for _, suffix := range []string{".sig", ".att", ".sbom"} {
		tag := d.Algorithm + "-" + d.Hex + suffix
		desc, err := s.src.Get(ctx, s.req.Source.Tag(tag))
		if notFound(err) {
			continue
		}
		if err != nil {
			return n, fmt.Errorf("fetch %s: %w", tag, err)
		}
		if err := s.copy(ctx, desc); err != nil {
			return n, err
		}
		if err := s.push.Put(ctx, s.req.Target.Tag(tag), desc); err != nil {
			return n, fmt.Errorf("tag %s: %w", tag, err)
		}
		n++
	}
	return n, nil
}

func notFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}

// short keeps result messages small. Registry references never carry
// userinfo and credentials travel only in headers, so errors hold none.
func short(err error) string {
	msg := err.Error()
	if len(msg) > maxMessage {
		msg = msg[:maxMessage] + "..."
	}
	return msg
}
