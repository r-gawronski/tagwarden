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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// pruneHeldNote is added to the Synced message when another mirror of the
// same target repository selects tags by pattern, so prune does nothing.
const pruneHeldNote = "prune skipped: another mirror of the same target repository selects tags by pattern"

// prunable returns the tags the sync Job may delete (threat model T13):
// the tags m recorded in status.owned, minus the tags another mirror holds
// (heldTags) and minus the tags m lists in spec.tags.tags, which the owner
// asked for by name. It is empty unless spec.tags.prune is on and m is not
// suspended; the caller has already checked that the target allows m. held
// is true when a pattern mirror holds every tag, so nothing is prunable.
func (r *ArtifactMirrorReconciler) prunable(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (out []syncspec.SyncedTag, held bool, err error) {
	if !m.Spec.Tags.Prune || m.Spec.Suspend || len(m.Status.Owned) == 0 {
		return nil, false, nil
	}
	hold, all, err := r.heldTags(ctx, t, m)
	if err != nil || all {
		return nil, all, err
	}
	for _, o := range m.Status.Owned {
		if !hold[o.Tag] && !slices.Contains(m.Spec.Tags.Tags, o.Tag) {
			out = append(out, syncspec.SyncedTag{Tag: o.Tag, Digest: o.Digest})
		}
	}
	return out, false, nil
}

// notePruneHeld adds pruneHeldNote to the Synced condition once.
func notePruneHeld(m *mirrorv1alpha1.ArtifactMirror) {
	c := meta.FindStatusCondition(m.Status.Conditions, ConditionSynced)
	if c == nil || strings.Contains(c.Message, pruneHeldNote) {
		return
	}
	c.Message = strings.TrimPrefix(c.Message+"; ", "; ") + pruneHeldNote
}

// reasonTagPruned is the Event reason for a tag a sync deleted.
const reasonTagPruned = "TagPruned"

// checkPruned refuses a report that prunes what the controller did not
// offer (threat model T12): prune must be on, and every pruned tag must be
// in status.owned with the same digest, not named in spec.tags.tags and not
// in the run's own synced list. It runs before the report is applied, so
// owned still holds what the Job was sent. A re-scan prunes nothing;
// ParseReport refuses it. Dropped tags are only forgotten, and mergeOwned
// ignores any that do not match the record.
func checkPruned(m *mirrorv1alpha1.ArtifactMirror, rep syncspec.Report) error {
	for _, p := range rep.Pruned {
		switch {
		case !m.Spec.Tags.Prune:
			return errors.New("report: pruned tags with prune off")
		case !slices.Contains(m.Status.Owned, mirrorv1alpha1.SyncedTag{Tag: p.Tag, Digest: p.Digest}),
			slices.Contains(m.Spec.Tags.Tags, p.Tag),
			slices.ContainsFunc(rep.Synced, func(s syncspec.SyncedTag) bool { return s.Tag == p.Tag }):
			return errors.New("report: pruned a tag that was not offered")
		}
	}
	return nil
}

// prunedEvents queues one Normal Event per pruned tag, at most
// maxGateEvents.
func prunedEvents(ev *pending, pruned []syncspec.SyncedTag) {
	for _, p := range pruned[:min(len(pruned), maxGateEvents)] {
		ev.add(corev1.EventTypeNormal, reasonTagPruned, "Sync",
			fmt.Sprintf("tag %s (%s) deleted from the target, no longer selected; the digest stays", p.Tag, p.Digest))
	}
}
