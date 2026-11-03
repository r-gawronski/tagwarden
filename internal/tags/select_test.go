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

package tags

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	latest       = "latest"
	latestRe     = "^latest$"
	fieldInclude = "include"
)

var all = []string{"v1.9.0", "v1.10.0", "v1.10.1", "v1.11.0-rc.1", "v1.11.0", latest, "v1.12.0"} //nolint:goconst // readable fixtures

func TestSelect(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		want   []string
	}{
		{"no policy keeps all, semver first", Policy{},
			[]string{"v1.12.0", "v1.11.0", "v1.11.0-rc.1", "v1.10.1", "v1.10.0", "v1.9.0", latest}},
		{"include final releases, keep 3", Policy{Include: []string{`^v\d+\.\d+\.\d+$`}, KeepLatest: 3},
			[]string{"v1.12.0", "v1.11.0", "v1.10.1"}},
		{"semver range", Policy{SemverRange: ">=1.10.0 <1.11.0"},
			[]string{"v1.10.1", "v1.10.0"}},
		{"exclude rc, keep 2", Policy{Exclude: []string{"-rc"}, KeepLatest: 2},
			[]string{"v1.12.0", "v1.11.0"}},
		{"include latest", Policy{Include: []string{latestRe}},
			[]string{latest}},
		{"keepLatest drops non-semver", Policy{Include: []string{latestRe}, KeepLatest: 5},
			[]string{}},
		{"any include matches", Policy{Include: []string{"^v1\\.9\\.", latestRe}},
			[]string{"v1.9.0", latest}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Select(all, tc.policy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestSelectErrors(t *testing.T) {
	long := strings.Repeat("a", MaxPatternLength+1)
	many := make([]string, MaxPatterns+1)
	for i := range many {
		many[i] = "a"
	}
	cases := []struct {
		name   string
		tags   []string
		policy Policy
		field  string
	}{
		{"invalid include", all, Policy{Include: []string{"("}}, fieldInclude},
		{"invalid exclude", all, Policy{Exclude: []string{"["}}, "exclude"},
		{"invalid range", all, Policy{SemverRange: "not-a-range"}, "semverRange"},
		{"too many includes", all, Policy{Include: many}, fieldInclude},
		{"too many excludes", all, Policy{Exclude: many}, "exclude"},
		{"pattern too long", all, Policy{Include: []string{long}}, fieldInclude},
		{"range too long", all, Policy{SemverRange: ">=" + strings.Repeat("1", MaxRangeLength)}, "semverRange"},
		{"negative keepLatest", all, Policy{KeepLatest: -1}, "keepLatest"},
		{"too many tags", make([]string, MaxTags+1), Policy{}, "tags"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select(tc.tags, tc.policy)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.HasPrefix(err.Error(), tc.field) {
				t.Fatalf("error %q does not name field %q", err, tc.field)
			}
		})
	}
}

func FuzzSelect(f *testing.F) {
	f.Add(strings.Join(all, "\n"), `^v\d+\.\d+\.\d+$`, "-rc", "", 3)
	f.Add(strings.Join(all, "\n"), "", "", ">=1.10.0 <1.11.0", 0)
	f.Add("latest\nmain\nv2", latestRe, "", "", 5)
	f.Fuzz(func(t *testing.T, tagList, include, exclude, rng string, keep int) {
		in := strings.Split(tagList, "\n")
		p := Policy{SemverRange: rng, KeepLatest: keep}
		if include != "" {
			p.Include = []string{include}
		}
		if exclude != "" {
			p.Exclude = []string{exclude}
		}
		out, err := Select(in, p)
		if err != nil {
			return
		}
		if len(out) > len(in) {
			t.Fatalf("output longer than input: %d > %d", len(out), len(in))
		}
		if keep > 0 && len(out) > keep {
			t.Fatalf("keepLatest %d not respected: %d tags", keep, len(out))
		}
		seen := map[string]bool{}
		unique := true
		for _, s := range in {
			if seen[s] {
				unique = false
			}
			seen[s] = true
		}
		if !unique {
			return
		}
		got := map[string]bool{}
		for _, s := range out {
			if got[s] {
				t.Fatalf("duplicate %s in output %v", strconv.Quote(s), out)
			}
			got[s] = true
		}
	})
}
