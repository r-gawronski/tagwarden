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
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// labelTarget is the ClusterMirrorTarget label of the target metrics.
const labelTarget = "target"

// gateUnscanned is 1 for a target whose vulnerability gate is enabled
// without a usable scanner configuration, so an alert can fire. The label
// is removed otherwise.
var gateUnscanned = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tagwarden_vulnerability_gate_unscanned",
	Help: "1 while a ClusterMirrorTarget has the vulnerability gate enabled but no usable scanner configuration; its generated mirrors are copied unscanned (onScanError Report) or not at all (Block).",
}, []string{labelTarget})

// sbomNotConfigured is 1 for a target whose SBOM policy is on without a
// generator image, so an alert can fire. The label is removed otherwise.
var sbomNotConfigured = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tagwarden_sbom_not_configured",
	Help: "1 while a ClusterMirrorTarget has an SBOM policy (mode PreferUpstream or Generate) but no generator image and version, from spec.sbom.generator or the chart's trivy.image.",
}, []string{labelTarget})

// scannerStartFailures counts sync Jobs deleted because their scanner
// sidecar did not start, by the waiting reason of the sidecar.
var scannerStartFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "tagwarden_scanner_start_failures_total",
	Help: "Gated sync Jobs deleted because the scanner sidecar did not start (image pull failure, bad config, crash loop), by target and waiting reason. Nothing is copied by such a run.",
}, []string{labelTarget, "reason"})

// selectedTags is the number of tags the last sync of a mirror selected.
var selectedTags = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tagwarden_mirror_selected_tags",
	Help: "Tags the last sync of an ArtifactMirror selected; 0 means the filters matched nothing (condition Synced, reason NoTagsSelected).",
}, []string{"namespace", "mirror"})

func init() {
	metrics.Registry.MustRegister(gateUnscanned, sbomNotConfigured, scannerStartFailures, selectedTags)
}
