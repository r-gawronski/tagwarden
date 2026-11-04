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
	"time"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

// Rescan judges again the tags of a gated mirror that are on the target.
// It reads each tag from the target, never from upstream, scans the
// digest the target holds, ignores judged verdicts and copies nothing. A
// tag with findings stays, or under Gate.Untag is deleted from the target
// when Gate.Untaggable lists it. Only the tag goes, never the digest.
// Untagged tags are in Result.Untagged; every other tag on the target is
// in Result.Skipped.
func Rescan(ctx context.Context, r Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if r.Gate == nil {
		return Result{}, errors.New("rescan: needs the vulnerability gate")
	}
	// ponytail: generated mirrors only have explicit tags, so the target is
	// never listed; a pattern policy would need a target listing.
	if p := r.Policy; len(p.Include) > 0 || p.SemverRange != "" || p.KeepLatest > 0 {
		return Result{}, errors.New("rescan: needs an explicit tag list")
	}
	s, err := newSyncer(r)
	if err != nil {
		return Result{}, err
	}
	selected, err := tags.Select(r.Policy.Tags, r.Policy)
	if err != nil {
		return Result{}, err
	}
	res := Result{Selected: selected}
	for _, tag := range selected {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := s.rescanTag(ctx, tag, &res); err != nil {
			res.Failed = append(res.Failed, Artifact{Tag: tag})
			res.Errors = append(res.Errors, tag+": "+short(err))
		}
		stamp(&res, tag, time.Now())
	}
	res.Gate, res.JavaScanned = s.gate.reason, s.gate.javaScanned
	if s.gate.root != nil {
		_ = s.gate.root.Close()
	}
	// A tag that could not be scanned is not judged: the run fails.
	var errs []error
	if err := blockedError(&res, res.Skipped); err != nil {
		errs = append(errs, err)
	}
	if len(res.Failed) > 0 {
		errs = append(errs, fmt.Errorf("rescan: %d of %d tags failed", len(res.Failed), len(selected)))
	}
	return res, errors.Join(errs...)
}

func (s *syncer) rescanTag(ctx context.Context, tag string, res *Result) error {
	dst, err := resolve(ctx, s.dst, s.req.Target.Tag(tag))
	switch {
	case notFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("check target tag: %w", err)
	}
	a := Artifact{Tag: tag, Digest: dst.Digest.String()}
	if a.Scan, err = s.scanPresent(ctx, s.dst, s.req.Target, a.Digest); err != nil {
		return err
	}
	if a.Scan.Verdict == vuln.FindingsFound {
		a.Untag = s.untag(ctx, a, res)
		if a.Untag == v1alpha1.VulnerableUntagged {
			res.Untagged = append(res.Untagged, a)
			return nil
		}
	}
	res.Skipped = append(res.Skipped, a)
	return nil
}

// untag applies onVulnerableTag to a tag with findings. It deletes the
// tag only under Untag, only when Untaggable lists it, and only while the
// tag still points at the scanned digest. A refused delete keeps the tag,
// as under Report, and is listed in res.Errors.
func (s *syncer) untag(ctx context.Context, a Artifact, res *Result) v1alpha1.VulnerableTagAction {
	g := s.gate
	switch {
	case !g.Untag:
		return v1alpha1.VulnerableKept
	case !g.Untaggable[a.Tag]:
		return v1alpha1.VulnerableUntagRefused
	}
	ref := s.req.Target.Tag(a.Tag)
	// A sync of the mirror may have moved the tag since the scan.
	if d, err := resolve(ctx, s.dst, ref); err != nil || d.Digest.String() != a.Digest {
		return v1alpha1.VulnerableUntagRefused
	}
	if err := s.pusher.Delete(ctx, ref); err != nil {
		res.Errors = append(res.Errors, a.Tag+": untag failed, kept: "+short(err))
		return v1alpha1.VulnerableUntagFailed
	}
	return v1alpha1.VulnerableUntagged
}
