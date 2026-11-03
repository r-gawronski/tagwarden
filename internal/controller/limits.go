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
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

// Defaults of ClusterMirrorTarget.spec.limits.
const (
	defaultMinSyncInterval        = time.Hour
	defaultMaxMirrorsPerNamespace = 50
	defaultMaxKeepLatest          = 20
	defaultMaxExplicitTags        = 50

	// scheduleHorizon is how far ahead minGap looks. Every pattern of
	// month days and weekdays, 29 February included, recurs within it.
	scheduleHorizon = 5 * 365 * 24 * time.Hour
	// maxScheduleRuns bounds the work of minGap. It is above the runs of a
	// schedule every 5 minutes, the smallest minSyncInterval, in five years.
	maxScheduleRuns = 600000
)

// minGap returns the shortest gap between consecutive runs of a cron
// schedule from from to scheduleHorizon later, or the first gap below
// stop. It parses the schedule the way the Kubernetes CronJob controller
// does. A schedule that never runs has no gap and returns math.MaxInt64.
// Gaps are measured in the location of from; a daylight saving change in
// the time zone of the CronJob controller can shorten one gap.
func minGap(schedule string, from time.Time, stop time.Duration) (time.Duration, error) {
	s, err := cron.ParseStandard(schedule)
	if err != nil {
		return 0, err
	}
	end := from.Add(scheduleHorizon)
	gap := time.Duration(math.MaxInt64)
	prev := s.Next(from)
	// One minute is the smallest gap cron can express.
	for i := 0; i < maxScheduleRuns && !prev.IsZero() && gap >= stop && gap > time.Minute; i++ {
		next := s.Next(prev)
		if next.IsZero() || next.After(end) {
			break
		}
		gap = min(gap, next.Sub(prev))
		prev = next
	}
	return gap, nil
}

type gapKey struct {
	schedule string
	limit    time.Duration
	day      string // UTC date, YYYY-MM-DD
}

var (
	gapCacheMu  sync.Mutex
	gapCache    = map[gapKey]time.Duration{}
	gapCacheDay string
)

// cachedMinGap is minGap memoized per schedule, limit and UTC date. A
// result changes negligibly within a day, and conflict ranking asks for
// the same schedule once per mirror on a target path.
// ponytail: one entry per distinct key, so the map grows with distinct
// schedules until the date changes and the purge below empties it.
// Upgrade path: a small LRU if one day of schedules ever gets large.
func cachedMinGap(schedule string, now time.Time, stop time.Duration) (time.Duration, error) {
	day := now.UTC().Format(time.DateOnly)
	key := gapKey{schedule, stop, day}
	gapCacheMu.Lock()
	if gapCacheDay != day {
		clear(gapCache)
		gapCacheDay = day
	}
	if g, ok := gapCache[key]; ok {
		gapCacheMu.Unlock()
		return g, nil
	}
	gapCacheMu.Unlock()
	g, err := minGap(schedule, now, stop)
	if err != nil {
		return 0, err
	}
	gapCacheMu.Lock()
	if gapCacheDay == day {
		gapCache[key] = g
	}
	gapCacheMu.Unlock()
	return g, nil
}

func resetGapCache() {
	gapCacheMu.Lock()
	defer gapCacheMu.Unlock()
	clear(gapCache)
	gapCacheDay = ""
}

// minSyncInterval is limits.minSyncInterval of t or its default.
func minSyncInterval(t *mirrorv1alpha1.ClusterMirrorTarget) time.Duration {
	if l := t.Spec.Limits; l != nil && l.MinSyncInterval != nil {
		return l.MinSyncInterval.Duration
	}
	return defaultMinSyncInterval
}

func limitOr(v *int32, def int32) int32 {
	if v == nil {
		return def
	}
	return *v
}

// checkLimits refuses a mirror that asks for more than the limits of its
// target allow (threat model T10). The oldest maxMirrorsPerNamespace
// mirrors of a namespace that use the target are allowed.
func (r *ArtifactMirrorReconciler) checkLimits(ctx context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (string, string, error) {
	l := t.Spec.Limits
	if l == nil {
		l = &mirrorv1alpha1.TargetLimits{}
	}
	interval := minSyncInterval(t)
	gap, err := cachedMinGap(m.Spec.Schedule, time.Now().UTC(), interval)
	if err != nil {
		return ReasonInvalidSpec, fmt.Sprintf("schedule %q: %v", m.Spec.Schedule, err), nil
	}
	if gap < interval {
		return ReasonScheduleTooFrequent, fmt.Sprintf("schedule %q runs %s apart at least once, below minSyncInterval %s of ClusterMirrorTarget %s",
			m.Spec.Schedule, gap, interval, t.Name), nil
	}
	if k, maxK := m.Spec.Tags.KeepLatest, limitOr(l.MaxKeepLatest, defaultMaxKeepLatest); k != nil && *k > maxK {
		return ReasonLimitExceeded, fmt.Sprintf("tags.keepLatest %d exceeds maxKeepLatest %d of ClusterMirrorTarget %s", *k, maxK, t.Name), nil
	}
	if n, maxN := len(m.Spec.Tags.Tags), limitOr(l.MaxExplicitTags, defaultMaxExplicitTags); n > int(maxN) {
		return ReasonLimitExceeded, fmt.Sprintf("tags.tags has %d entries, more than maxExplicitTags %d of ClusterMirrorTarget %s", n, maxN, t.Name), nil
	}

	var list mirrorv1alpha1.ArtifactMirrorList
	if err := r.List(ctx, &list, client.InNamespace(m.Namespace), client.MatchingFields{indexTargetName: t.Name}); err != nil {
		return "", "", err
	}
	ahead := 0
	for i := range list.Items {
		o := &list.Items[i]
		if o.UID != m.UID && o.DeletionTimestamp.IsZero() && older(o, m) {
			ahead++
		}
	}
	if maxM := limitOr(l.MaxMirrorsPerNamespace, defaultMaxMirrorsPerNamespace); ahead >= int(maxM) {
		return ReasonLimitExceeded, fmt.Sprintf("maxMirrorsPerNamespace %d of ClusterMirrorTarget %s is used up by older ArtifactMirrors in namespace %s",
			maxM, t.Name, m.Namespace), nil
	}
	return "", "", nil
}
