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
)

func TestMergeOwned(t *testing.T) {
	st := func(tag, d string) mirrorv1alpha1.SyncedTag { return mirrorv1alpha1.SyncedTag{Tag: tag, Digest: d} }
	type L = []mirrorv1alpha1.SyncedTag
	for _, tc := range []struct {
		name                          string
		owned, synced, pruned, absent L
		want                          L
	}{
		{name: "first run records synced", synced: L{st("2", "b"), st("1", "a")}, want: L{st("2", "b"), st("1", "a")}},
		{name: "older owned tags stay after the synced ones", owned: L{st("1", "a")}, synced: L{st("3", "c"), st("2", "b")},
			want: L{st("3", "c"), st("2", "b"), st("1", "a")}},
		{name: "run digest wins", owned: L{st("2", "old")}, synced: L{st("2", "new")}, want: L{st("2", "new")}},
		{name: "pruned tags leave", owned: L{st("1", "a"), st("2", "b")}, synced: L{st("3", "c")}, pruned: L{st("1", "a")},
			want: L{st("3", "c"), st("2", "b")}},
		{name: "tags gone or moved leave", owned: L{st("1", "a"), st("2", "b")}, absent: L{st("2", "b")}, want: L{st("1", "a")}},
		{name: "nothing synced keeps the record", owned: L{st("1", "a")}, want: L{st("1", "a")}},
		{name: "empty", want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := mergeOwned(tc.owned, tc.synced, tc.pruned, tc.absent)
			if truncated || !slices.Equal(got, tc.want) {
				t.Errorf("got %v truncated=%v, want %v", got, truncated, tc.want)
			}
		})
	}
}

func TestMergeOwnedCap(t *testing.T) {
	var synced, owned []mirrorv1alpha1.SyncedTag
	for i := range maxOwned + 5 {
		s := mirrorv1alpha1.SyncedTag{Tag: fmt.Sprint("t", i), Digest: "d"}
		if i < maxOwned-10 {
			synced = append(synced, s)
		} else {
			owned = append(owned, s)
		}
	}
	got, truncated := mergeOwned(owned, synced, nil, nil)
	if !truncated || len(got) != maxOwned {
		t.Fatalf("len %d truncated=%v, want %d true", len(got), truncated, maxOwned)
	}
	// The record is cut at the old end, so the synced tags stay.
	if got[0] != synced[0] || got[len(synced)-1] != synced[len(synced)-1] {
		t.Error("synced tags were cut")
	}
	if _, truncated := mergeOwned(got[:maxOwned], nil, nil, nil); truncated {
		t.Error("a record at the cap is not truncated")
	}
}
