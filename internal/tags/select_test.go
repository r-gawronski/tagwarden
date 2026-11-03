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

	"github.com/Masterminds/semver/v3"
)

const (
	latest       = "latest"
	latestRe     = "^latest$"
	fieldInclude = "include"
)

var all = []string{"v1.9.0", "v1.10.0", "v1.10.1", "v1.11.0-rc.1", "v1.11.0", latest, "v1.12.0"} //nolint:goconst // readable fixtures

var mixed = []string{"1.2", "1.2.0", "v1.2.0", "20240101", "7", "sha-abc", "1.10.0", "v1.11.0+build"} //nolint:goconst // readable fixtures

func TestSelect(t *testing.T) {
	cases := []struct {
		name   string
		in     []string
		policy Policy
		want   []string
	}{
		{"no selector selects nothing", all, Policy{}, []string{}},
		{"exclude alone selects nothing", all, Policy{Exclude: []string{"-rc"}}, []string{}},
		{"include all, semver first", all, Policy{Include: []string{"."}},
			[]string{"v1.12.0", "v1.11.0", "v1.11.0-rc.1", "v1.10.1", "v1.10.0", "v1.9.0", latest}},
		{"include final releases, keep 3", all, Policy{Include: []string{`^v\d+\.\d+\.\d+$`}, KeepLatest: 3},
			[]string{"v1.12.0", "v1.11.0", "v1.10.1"}},
		{"semver range", all, Policy{SemverRange: ">=1.10.0 <1.11.0"},
			[]string{"v1.10.1", "v1.10.0"}},
		{"exclude rc, keep 2", all, Policy{Exclude: []string{"-rc"}, KeepLatest: 2},
			[]string{"v1.12.0", "v1.11.0"}},
		{"include latest", all, Policy{Include: []string{latestRe}},
			[]string{latest}},
		{"keepLatest drops non-semver", all, Policy{Include: []string{latestRe}, KeepLatest: 5},
			[]string{}},
		{"any include matches", all, Policy{Include: []string{"^v1\\.9\\.", latestRe}},
			[]string{"v1.9.0", latest}},
		{"keepLatest drops prereleases", all, Policy{KeepLatest: 3},
			[]string{"v1.12.0", "v1.11.0", "v1.10.1"}},
		{"keepLatest with prereleases", all, Policy{KeepLatest: 3, AllowPrerelease: true},
			[]string{"v1.12.0", "v1.11.0", "v1.11.0-rc.1"}},
		{"range drops prereleases", all, Policy{SemverRange: ">=1.11.0-0 <1.12.0"},
			[]string{"v1.11.0"}},
		{"range with prereleases", all, Policy{SemverRange: ">=1.10.1 <1.12.0", AllowPrerelease: true},
			[]string{"v1.11.0", "v1.11.0-rc.1", "v1.10.1"}},
		{"plain numbers are not semver", mixed, Policy{KeepLatest: 3},
			[]string{"v1.11.0+build", "1.10.0", "1.2"}},
		{"equal versions take separate slots", mixed, Policy{SemverRange: "1.2.0"},
			[]string{"1.2", "1.2.0", "v1.2.0"}},
		{"leading zeros are not semver", []string{"01.02.03", "1.02.3", "1.2.03", "1.2.3", "0.10.0"}, Policy{KeepLatest: 5},
			[]string{"1.2.3", "0.10.0"}},
		{"non-semver sorted by name", mixed, Policy{Include: []string{`^\d+$`, "^sha-"}},
			[]string{"20240101", "7", "sha-abc"}},
		{"explicit tags only", all, Policy{Tags: []string{latest, "v1.9.0", "v1.9.0", "missing"}},
			[]string{"v1.9.0", latest}},
		{"explicit tags on top of selection", all, Policy{KeepLatest: 1, Tags: []string{latest, "v1.12.0", "v1.9.0"}},
			[]string{"v1.12.0", "v1.9.0", latest}},
		{"explicit tags ignore exclude", all, Policy{Exclude: []string{"rc"}, Tags: []string{"v1.11.0-rc.1"}},
			[]string{"v1.11.0-rc.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Select(tc.in, tc.policy)
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
		{"program too large", all, Policy{Include: []string{`\w{1000}\w{1000}`}}, fieldInclude},
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
			if tc.field != "tags" && Validate(tc.policy) == nil {
				t.Fatal("Validate accepts the policy")
			}
		})
	}
}

func FuzzSelect(f *testing.F) {
	f.Add(strings.Join(all, "\n"), `^v\d+\.\d+\.\d+$`, "-rc", "", "", 3, false)
	f.Add(strings.Join(all, "\n"), "", "", ">=1.10.0 <1.11.0", "", 0, true)
	f.Add(strings.Join(mixed, "\n"), latestRe, "", "", "7\nlatest", 5, false)
	f.Fuzz(func(t *testing.T, tagList, include, exclude, rng, explicit string, keep int, pre bool) {
		in := strings.Split(tagList, "\n")
		p := Policy{SemverRange: rng, KeepLatest: keep, AllowPrerelease: pre}
		if include != "" {
			p.Include = []string{include}
		}
		if exclude != "" {
			p.Exclude = []string{exclude}
		}
		if explicit != "" {
			p.Tags = strings.Split(explicit, "\n")
		}
		out, err := Select(in, p)
		if err != nil {
			return
		}
		if len(out) > len(in) {
			t.Fatalf("output longer than input: %d > %d", len(out), len(in))
		}
		if keep > 0 && len(out) > keep+len(p.Tags) {
			t.Fatalf("keepLatest %d not respected: %d tags", keep, len(out))
		}
		var prev *semver.Version
		inSemver := true
		for _, s := range out {
			if !slices.Contains(in, s) {
				t.Fatalf("output tag %s not in input", strconv.Quote(s))
			}
			v := parse(s)
			if v == nil {
				inSemver = false
				continue
			}
			if !inSemver {
				t.Fatalf("semver tag %s after non-semver tag in %v", strconv.Quote(s), out)
			}
			if prev != nil && v.GreaterThan(prev) {
				t.Fatalf("not descending: %v", out)
			}
			prev = v
		}
		seen := map[string]bool{}
		for _, s := range in {
			if seen[s] {
				return
			}
			seen[s] = true
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
