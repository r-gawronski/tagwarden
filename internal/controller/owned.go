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
	"slices"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

// maxOwned caps status.owned, as the CRD schema does.
const maxOwned = 200

// mergeOwned returns the record of tags a mirror put on the target after a
// sync: the run's synced tags (the run's digest wins), then the earlier
// entries that are still on the target, each in its earlier order, minus the
// tags the run pruned and the tags it found gone or moved. Past maxOwned the
// end of the list is cut, which holds the oldest versions, and truncated is
// true. A cut tag is never pruned: it fails safe.
func mergeOwned(owned, synced, pruned, absent []mirrorv1alpha1.SyncedTag) (out []mirrorv1alpha1.SyncedTag, truncated bool) {
	drop := map[string]bool{}
	for _, s := range slices.Concat(pruned, absent) {
		drop[s.Tag] = true
	}
	seen := map[string]bool{}
	for _, s := range slices.Concat(synced, owned) {
		if drop[s.Tag] || seen[s.Tag] {
			continue
		}
		seen[s.Tag] = true
		out = append(out, s)
	}
	if len(out) > maxOwned {
		out, truncated = out[:maxOwned], true
	}
	return out, truncated
}
