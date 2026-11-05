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

// Package tags selects which upstream tags to mirror.
package tags

import (
	"cmp"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"

	"github.com/Masterminds/semver/v3"
)

// Safety caps from the threat model (T7, T22).
const (
	MaxPatterns      = 20
	MaxPatternLength = 256
	MaxProgramInsts  = 2000
	MaxRangeLength   = 256
	// MaxTags is the default cap of a tag listing; MaxTagsLimit is the
	// highest cap a target may set (maxListedTags).
	MaxTags      = 10000
	MaxTagsLimit = 100000
)

// semverTag is the tag shape treated as a version. It rejects plain numbers
// such as "7" or "20240101" and leading zeros such as "01.02.03", which
// semver.NewVersion would coerce.
var semverTag = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)(\.(0|[1-9]\d*))?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// Policy describes which tags to keep.
type Policy struct {
	// Include keeps a tag if any pattern matches.
	Include []string `json:"include,omitempty"`
	// Exclude drops a tag if any pattern matches.
	Exclude []string `json:"exclude,omitempty"`
	// SemverRange keeps semver tags within the constraint.
	SemverRange string `json:"semverRange,omitempty"`
	// KeepLatest keeps only the N highest semver tags. Zero means no limit.
	KeepLatest int `json:"keepLatest,omitempty"`
	// AllowPrerelease keeps prerelease versions when SemverRange or KeepLatest is set.
	AllowPrerelease bool `json:"allowPrerelease,omitempty"`
	// Tags are always selected when present in the input, on top of the patterns.
	Tags []string `json:"tags,omitempty"`
}

// Stats counts what Explain did with the input. A tag is counted once, by the
// first filter that removed it.
type Stats struct {
	// Listed is the number of input tags.
	Listed int
	// Filtered were removed by include or exclude.
	Filtered int
	// NotSemver were removed because keepLatest or semverRange needs a version.
	NotSemver int
	// Prerelease were removed because allowPrerelease is not set.
	Prerelease int
	// OutOfRange were removed by semverRange.
	OutOfRange int
	// Trimmed were removed by keepLatest.
	Trimmed int
	// Selected is the number of returned tags.
	Selected int
	// Missing lists explicit tags that are not in the input.
	Missing []string
}

// Select returns the tags chosen by p.
//
// Pattern selection applies only when Include, SemverRange or KeepLatest is
// set. Without them only the explicit Tags are returned, never every tag.
// Patterns are Go RE2 regexes and are not anchored. When SemverRange or
// KeepLatest is set, tags that are not semver are dropped, and so are
// prereleases unless AllowPrerelease is set. Explicit Tags bypass all filters.
//
// The result lists semver tags in descending order, then the other tags by
// name. Tags such as "1.2", "1.2.0" and "v1.2.0" are distinct: each takes its
// own KeepLatest slot, and equal versions are ordered by name.
func Select(tags []string, p Policy) ([]string, error) {
	out, _, err := Explain(tags, p)
	return out, err
}

// Explain is Select with the per-filter counts.
func Explain(tags []string, p Policy) ([]string, Stats, error) {
	st := Stats{Listed: len(tags)}
	if len(tags) > MaxTagsLimit {
		return nil, st, fmt.Errorf("tags: %d entries exceed the limit of %d", len(tags), MaxTagsLimit)
	}
	include, exclude, constraint, err := p.compile()
	if err != nil {
		return nil, st, err
	}
	semverOnly := constraint != nil || p.KeepLatest > 0
	patterns := semverOnly || len(include) > 0

	var versions []versioned
	var others []string
	for _, t := range tags {
		if !patterns {
			continue
		}
		if len(include) > 0 && !matchAny(include, t) || matchAny(exclude, t) {
			st.Filtered++
			continue
		}
		v := parse(t)
		switch {
		case v == nil:
			if semverOnly {
				st.NotSemver++
			} else {
				others = append(others, t)
			}
		case semverOnly && !p.AllowPrerelease && v.Prerelease() != "":
			st.Prerelease++
		case constraint != nil && !constraint.Check(v):
			st.OutOfRange++
		default:
			versions = append(versions, versioned{t, v})
		}
	}
	sortVersions(versions)
	if p.KeepLatest > 0 && len(versions) > p.KeepLatest {
		st.Trimmed = len(versions) - p.KeepLatest
		versions = versions[:p.KeepLatest]
	}

	selected := make(map[string]bool, len(versions)+len(others))
	for _, v := range versions {
		selected[v.tag] = true
	}
	for _, t := range others {
		selected[t] = true
	}
	for _, t := range p.Tags {
		if !slices.Contains(tags, t) && !slices.Contains(st.Missing, t) {
			st.Missing = append(st.Missing, t)
		}
	}
	for _, t := range tags {
		if !selected[t] && slices.Contains(p.Tags, t) {
			selected[t] = true
			if v := parse(t); v != nil {
				versions = append(versions, versioned{t, v})
			} else {
				others = append(others, t)
			}
		}
	}
	sortVersions(versions)
	slices.Sort(others)

	out := make([]string, 0, len(versions)+len(others))
	for _, v := range versions {
		out = append(out, v.tag)
	}
	out = append(out, others...)
	st.Selected = len(out)
	return out, st, nil
}

// Validate reports whether p is a valid policy: its patterns compile within
// the caps and its range parses.
func Validate(p Policy) error {
	_, _, _, err := p.compile()
	return err
}

// compile validates p and compiles its patterns and range.
func (p Policy) compile() (include, exclude []*regexp.Regexp, constraint *semver.Constraints, err error) {
	if include, err = compilePatterns("include", p.Include); err != nil {
		return nil, nil, nil, err
	}
	if exclude, err = compilePatterns("exclude", p.Exclude); err != nil {
		return nil, nil, nil, err
	}
	if p.KeepLatest < 0 {
		return nil, nil, nil, fmt.Errorf("keepLatest: must not be negative, got %d", p.KeepLatest)
	}
	if p.SemverRange != "" {
		if len(p.SemverRange) > MaxRangeLength {
			return nil, nil, nil, fmt.Errorf("semverRange: longer than %d characters", MaxRangeLength)
		}
		if constraint, err = semver.NewConstraint(p.SemverRange); err != nil {
			return nil, nil, nil, fmt.Errorf("semverRange: %w", err)
		}
		constraint.IncludePrerelease = p.AllowPrerelease
	}
	return include, exclude, constraint, nil
}

type versioned struct {
	tag string
	v   *semver.Version
}

func sortVersions(vs []versioned) {
	slices.SortFunc(vs, func(a, b versioned) int {
		if c := b.v.Compare(a.v); c != 0 {
			return c
		}
		return cmp.Compare(a.tag, b.tag)
	})
}

// parse returns the version of a semver-shaped tag, or nil.
func parse(tag string) *semver.Version {
	if !semverTag.MatchString(tag) {
		return nil
	}
	v, err := semver.NewVersion(tag)
	if err != nil {
		return nil
	}
	return v
}

func compilePatterns(field string, patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) > MaxPatterns {
		return nil, fmt.Errorf("%s: %d patterns exceed the limit of %d", field, len(patterns), MaxPatterns)
	}
	res := make([]*regexp.Regexp, 0, len(patterns))
	for i, p := range patterns {
		if len(p) > MaxPatternLength {
			return nil, fmt.Errorf("%s[%d]: longer than %d characters", field, i, MaxPatternLength)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		parsed, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		if len(prog.Inst) > MaxProgramInsts {
			return nil, fmt.Errorf("%s[%d]: compiled program exceeds %d instructions", field, i, MaxProgramInsts)
		}
		res = append(res, re)
	}
	return res, nil
}

func matchAny(res []*regexp.Regexp, s string) bool {
	return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}
