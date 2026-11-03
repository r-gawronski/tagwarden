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
	"time"

	"github.com/robfig/cron/v3"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

// Defaults of ClusterMirrorTarget.spec.limits.
const (
	defaultMinSyncInterval = time.Hour

	// scheduleHorizon is how many runs of a schedule minGap looks at.
	scheduleHorizon = 1000
)

// minGap returns the shortest gap between consecutive runs of a cron
// schedule over the next scheduleHorizon runs after from. It parses the
// schedule the way the Kubernetes CronJob controller does. A schedule that
// never runs has no gap and returns math.MaxInt64. Gaps are measured in
// the location of from; a daylight saving change in the time zone of the
// CronJob controller can shorten one gap.
func minGap(schedule string, from time.Time) (time.Duration, error) {
	s, err := cron.ParseStandard(schedule)
	if err != nil {
		return 0, err
	}
	gap := time.Duration(math.MaxInt64)
	prev := s.Next(from)
	for i := 0; i < scheduleHorizon && !prev.IsZero(); i++ {
		next := s.Next(prev)
		if next.IsZero() {
			break
		}
		gap = min(gap, next.Sub(prev))
		prev = next
	}
	return gap, nil
}

// checkLimits refuses a mirror that asks for more than the limits of its
// target allow (threat model T10).
func (r *ArtifactMirrorReconciler) checkLimits(_ context.Context, t *mirrorv1alpha1.ClusterMirrorTarget, m *mirrorv1alpha1.ArtifactMirror) (string, string, error) {
	l := t.Spec.Limits
	if l == nil {
		l = &mirrorv1alpha1.TargetLimits{}
	}
	interval := defaultMinSyncInterval
	if l.MinSyncInterval != nil {
		interval = l.MinSyncInterval.Duration
	}
	gap, err := minGap(m.Spec.Schedule, time.Now().UTC())
	if err != nil {
		return ReasonInvalidSpec, fmt.Sprintf("schedule %q: %v", m.Spec.Schedule, err), nil
	}
	if gap < interval {
		return ReasonScheduleTooFrequent, fmt.Sprintf("schedule %q runs every %s at its most frequent, below minSyncInterval %s of ClusterMirrorTarget %s",
			m.Spec.Schedule, gap, interval, t.Name), nil
	}
	return "", "", nil
}
