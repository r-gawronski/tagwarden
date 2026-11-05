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

	"github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/tags"
)

// prune deletes the target tags in Request.Prunable that the selection no
// longer includes (threat model T13). It only deletes tags, never a
// digest, and only a tag that still points at the digest the mirror
// recorded; a tag that is gone or moved is listed in res.Dropped so the
// controller stops tracking it. A failed delete keeps the tag and is listed
// in res.Errors, without failing the run.
//
// The whole step is skipped unless the run was clean: the selection must
// not be empty, and no tag may have failed, been blocked or been refused as
// mutated. A bad upstream answer must not empty the target. A tag that is
// in the selection, or that the policy names, is never pruned. Neither is
// a tag the selection would pick had the source listed it, so a valid but
// incomplete listing cannot prune the newest tags; it is kept and reported
// in res.Errors.
func (s *syncer) prune(ctx context.Context, res *Result, mutated bool) {
	if len(s.req.Prunable) == 0 || len(res.Selected) == 0 || len(res.Failed) > 0 || len(res.Blocked) > 0 || mutated {
		return
	}
	// Select again over the listing plus the prunable tags it lacks.
	all := slices.Clone(s.listed)
	for _, p := range s.req.Prunable {
		if !slices.Contains(all, p.Tag) {
			all = append(all, p.Tag)
		}
	}
	would, _, err := tags.Explain(all, s.req.Policy)
	if err != nil {
		return
	}
	for _, p := range s.req.Prunable {
		if ctx.Err() != nil {
			return
		}
		if slices.Contains(res.Selected, p.Tag) || slices.Contains(s.req.Policy.Tags, p.Tag) {
			continue
		}
		if slices.Contains(would, p.Tag) {
			res.Errors = append(res.Errors, p.Tag+": prune kept, the selection would include it if the source listed it")
			continue
		}
		d, err := resolve(ctx, s.dst, s.req.Target.Tag(p.Tag))
		switch {
		case notFound(err):
			res.Dropped = append(res.Dropped, p)
			continue
		case err != nil:
			res.Errors = append(res.Errors, p.Tag+": prune failed, kept: "+short(err))
			continue
		case d.Digest.String() != p.Digest:
			res.Dropped = append(res.Dropped, p)
			continue
		}
		switch err := s.deleteTag(ctx, p.Tag, p.Digest); {
		case errors.Is(err, registry.ErrTagNotFound):
			res.Dropped = append(res.Dropped, p)
		case err != nil:
			res.Errors = append(res.Errors, p.Tag+": prune failed, kept: "+short(err))
		default:
			res.Pruned = append(res.Pruned, p)
		}
	}
}
