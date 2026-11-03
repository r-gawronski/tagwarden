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
	"strings"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
)

const (
	// ArgoCDTrackingInherit makes a sync CronJob join the Argo CD app of its mirror.
	ArgoCDTrackingInherit = "inherit"
	// DefaultArgoCDInstanceLabel is the label of Argo CD's label tracking mode.
	DefaultArgoCDInstanceLabel = "app.kubernetes.io/instance"

	annotationArgoTrackingID = "argocd.argoproj.io/tracking-id"
	annotationArgoCompare    = "argocd.argoproj.io/compare-options"
	annotationArgoSync       = "argocd.argoproj.io/sync-options"

	reasonTrackingMismatch = "ArgoCDTrackingMismatch"
)

// argoTracking returns the labels and annotations that show a mirror's
// CronJob in the Argo CD app of the mirror, with sync, prune and delete
// switched off. A tracking id that names another object yields nothing and
// is returned as mismatch.
func argoTracking(mode, instanceLabel string, m *mirrorv1alpha1.ArtifactMirror, namespace, cronJob string) (labels, annotations map[string]string, mismatch string) {
	if mode != ArgoCDTrackingInherit {
		return nil, nil, ""
	}
	if instanceLabel == "" {
		instanceLabel = DefaultArgoCDInstanceLabel
	}
	options := map[string]string{
		annotationArgoCompare: "IgnoreExtraneous",
		annotationArgoSync:    "Prune=false,Delete=false",
	}
	if id := m.Annotations[annotationArgoTrackingID]; id != "" {
		// <app>:<group>/<kind>:<namespace>/<name>; the app name may hold colons.
		parts := strings.Split(id, ":")
		if len(parts) < 3 || parts[0] == "" {
			return nil, nil, id
		}
		app, gk, nn := strings.Join(parts[:len(parts)-2], ":"), parts[len(parts)-2], parts[len(parts)-1]
		if gk != "mirror.tagwarden.dev/ArtifactMirror" || nn != m.Namespace+"/"+m.Name {
			return nil, nil, id
		}
		options[annotationArgoTrackingID] = app + ":batch/CronJob:" + namespace + "/" + cronJob
		return nil, options, ""
	}
	if v := m.Labels[instanceLabel]; v != "" {
		return map[string]string{instanceLabel: v}, options, ""
	}
	return nil, nil, ""
}

// trackingDrift reports whether the live CronJob metadata differs from the
// desired one in the keys argoTracking manages. A hand edit keeps the
// checksum annotation, so the checksum alone would let it persist.
func trackingDrift(live, want map[string]string, liveLabels, wantLabels map[string]string, instanceLabel string) bool {
	if instanceLabel == "" {
		instanceLabel = DefaultArgoCDInstanceLabel
	}
	for _, k := range []string{annotationArgoTrackingID, annotationArgoCompare, annotationArgoSync} {
		if live[k] != want[k] {
			return true
		}
	}
	return liveLabels[instanceLabel] != wantLabels[instanceLabel]
}
