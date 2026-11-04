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

// gateUnscanned is 1 for a target whose vulnerability gate is enabled
// without a usable scanner configuration, so an alert can fire. The label
// is removed otherwise.
var gateUnscanned = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "tagwarden_vulnerability_gate_unscanned",
	Help: "1 while a ClusterMirrorTarget has the vulnerability gate enabled but no usable scanner configuration; its generated mirrors are copied unscanned (onScanError Report) or not at all (Block).",
}, []string{"target"})

func init() { metrics.Registry.MustRegister(gateUnscanned) }
