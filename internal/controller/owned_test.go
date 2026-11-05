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
	"fmt"
	"slices"
	"testing"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

func TestMergeOwned(t *testing.T) {
	st := func(tag, d string) mirrorv1alpha1.SyncedTag { return mirrorv1alpha1.SyncedTag{Tag: tag, Digest: d} }
	cp := func(tag, d string) syncspec.SyncedTag { return syncspec.SyncedTag{Tag: tag, Digest: d, Copied: true} }
	sk := func(tag, d string) syncspec.SyncedTag { return syncspec.SyncedTag{Tag: tag, Digest: d} }
	type L = []mirrorv1alpha1.SyncedTag
	type R = []syncspec.SyncedTag
	for _, tc := range []struct {
		name                   string
		owned                  L
		synced, pruned, absent R
		want                   L
	}{
		{name: "first run records copied", synced: R{cp("2", "b"), cp("1", "a")}, want: L{st("2", "b"), st("1", "a")}},
		{name: "older owned tags stay after the copied ones", owned: L{st("1", "a")}, synced: R{cp("3", "c"), cp("2", "b")},
			want: L{st("3", "c"), st("2", "b"), st("1", "a")}},
		{name: "run digest wins for a copied tag", owned: L{st("2", "old")}, synced: R{cp("2", "new")}, want: L{st("2", "new")}},
		{name: "a skipped tag is not adopted", synced: R{sk("2", "b"), cp("1", "a")}, want: L{st("1", "a")}},
		{name: "a skipped tag keeps the recorded digest", owned: L{st("2", "mine")}, synced: R{sk("2", "human")}, want: L{st("2", "mine")}},
		{name: "pruned tags leave", owned: L{st("1", "a"), st("2", "b")}, synced: R{cp("3", "c")}, pruned: R{sk("1", "a")},
			want: L{st("3", "c"), st("2", "b")}},
		{name: "tags gone or moved leave", owned: L{st("1", "a"), st("2", "b")}, absent: R{sk("2", "b")}, want: L{st("1", "a")}},
		{name: "a dropped tag the run synced stays", owned: L{st("1", "a")}, synced: R{sk("1", "a")}, absent: R{sk("1", "a")}, want: L{st("1", "a")}},
		{name: "a dropped tag with another digest stays", owned: L{st("1", "a")}, absent: R{sk("1", "other")}, want: L{st("1", "a")}},
		{name: "a dropped tag that is not recorded changes nothing", owned: L{st("1", "a")}, absent: R{sk("x", "a")}, want: L{st("1", "a")}},
		{name: "nothing synced keeps the record", owned: L{st("1", "a")}, want: L{st("1", "a")}},
		{name: "empty", want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := mergeOwned(tc.owned, syncspec.Report{Synced: tc.synced, Pruned: tc.pruned, Dropped: tc.absent})
			if truncated || !slices.Equal(got, tc.want) {
				t.Errorf("got %v truncated=%v, want %v", got, truncated, tc.want)
			}
		})
	}
}

func TestMergeOwnedCap(t *testing.T) {
	var synced, owned []mirrorv1alpha1.SyncedTag
	var rep syncspec.Report
	for i := range maxOwned + 5 {
		s := mirrorv1alpha1.SyncedTag{Tag: fmt.Sprint("t", i), Digest: "d"}
		if i < maxOwned-10 {
			synced = append(synced, s)
			rep.Synced = append(rep.Synced, syncspec.SyncedTag{Tag: s.Tag, Digest: s.Digest, Copied: true})
		} else {
			owned = append(owned, s)
		}
	}
	got, truncated := mergeOwned(owned, rep)
	if !truncated || len(got) != maxOwned {
		t.Fatalf("len %d truncated=%v, want %d true", len(got), truncated, maxOwned)
	}
	// The record is cut at the old end, so the synced tags stay.
	if got[0] != synced[0] || got[len(synced)-1] != synced[len(synced)-1] {
		t.Error("synced tags were cut")
	}
	if _, truncated := mergeOwned(got[:maxOwned], syncspec.Report{}); truncated {
		t.Error("a record at the cap is not truncated")
	}
}
