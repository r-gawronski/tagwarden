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
	"slices"
	"strings"

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
