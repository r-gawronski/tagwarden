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
	"slices"

	"github.com/Masterminds/semver/v3"
)

// Safety caps from the threat model (T7, T22).
const (
	MaxPatterns      = 20
	MaxPatternLength = 256
	MaxRangeLength   = 256
	MaxTags          = 10000
)

// Policy describes which tags to keep.
type Policy struct {
	// Include keeps a tag if any pattern matches. Empty keeps all tags.
	Include []string
	// Exclude drops a tag if any pattern matches.
	Exclude []string
	// SemverRange keeps semver tags within the constraint.
	SemverRange string
	// KeepLatest keeps only the N highest semver tags. Zero means no limit.
	KeepLatest int
}

// Select returns the tags chosen by p: semver tags sorted descending, then,
// only when neither SemverRange nor KeepLatest is set, the other tags by name.
// Patterns are Go RE2 regexes and are not anchored.
func Select(tags []string, p Policy) ([]string, error) {
	if len(tags) > MaxTags {
		return nil, fmt.Errorf("tags: %d entries exceed the limit of %d", len(tags), MaxTags)
	}
	include, err := compile("include", p.Include)
	if err != nil {
		return nil, err
	}
	exclude, err := compile("exclude", p.Exclude)
	if err != nil {
		return nil, err
	}
	if p.KeepLatest < 0 {
		return nil, fmt.Errorf("keepLatest: must not be negative, got %d", p.KeepLatest)
	}
	var constraint *semver.Constraints
	if p.SemverRange != "" {
		if len(p.SemverRange) > MaxRangeLength {
			return nil, fmt.Errorf("semverRange: longer than %d characters", MaxRangeLength)
		}
		if constraint, err = semver.NewConstraint(p.SemverRange); err != nil {
			return nil, fmt.Errorf("semverRange: %w", err)
		}
	}
	semverOnly := constraint != nil || p.KeepLatest > 0

	type versioned struct {
		tag string
		v   *semver.Version
	}
	var versions []versioned
	others := []string{}
	for _, t := range tags {
		if (len(include) > 0 && !matchAny(include, t)) || matchAny(exclude, t) {
			continue
		}
		v, err := semver.NewVersion(t)
		if err != nil {
			if !semverOnly {
				others = append(others, t)
			}
			continue
		}
		if constraint != nil && !constraint.Check(v) {
			continue
		}
		versions = append(versions, versioned{t, v})
	}

	slices.SortFunc(versions, func(a, b versioned) int {
		if c := b.v.Compare(a.v); c != 0 {
			return c
		}
		return cmp.Compare(a.tag, b.tag)
	})
	if p.KeepLatest > 0 && len(versions) > p.KeepLatest {
		versions = versions[:p.KeepLatest]
	}
	slices.Sort(others)

	out := make([]string, 0, len(versions)+len(others))
	for _, v := range versions {
		out = append(out, v.tag)
	}
	return append(out, others...), nil
}

func compile(field string, patterns []string) ([]*regexp.Regexp, error) {
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
		res = append(res, re)
	}
	return res, nil
}

func matchAny(res []*regexp.Regexp, s string) bool {
	return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}
