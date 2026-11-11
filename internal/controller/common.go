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
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// conflictRequeue is the retry delay after a status update loses an
// optimistic-concurrency race, usually to the reconciler's own previous write
// that the cache has not caught up with.
const conflictRequeue = time.Second

// statusUpdateFailed turns a status-update conflict into a quiet requeue, so
// cache lag does not show up as a Reconciler error. Other errors pass through.
func statusUpdateFailed(ctx context.Context, err error) (ctrl.Result, error) {
	if apierrors.IsConflict(err) {
		log.FromContext(ctx).V(1).Info("Status update conflict, requeueing", "error", err.Error())
		return ctrl.Result{RequeueAfter: conflictRequeue}, nil
	}
	return ctrl.Result{}, err
}

// Condition types.
const (
	// ConditionReady reports whether the resource is usable.
	ConditionReady = "Ready"
	// ConditionSynced reports the result of the last finished sync.
	ConditionSynced = "Synced"
	// ConditionRescanned reports the result of the last finished re-scan.
	ConditionRescanned = "Rescanned"
	// ConditionVulnerabilitiesFound is True on a generated mirror when a
	// selected tag has findings.
	ConditionVulnerabilitiesFound = "VulnerabilitiesFound"
	// ConditionVulnerabilityGate is False on a generated mirror when tags
	// could not be judged.
	ConditionVulnerabilityGate = "VulnerabilityGate"
	// ConditionScannerReady reports on a gated target whether the Trivy
	// server is reachable and runs the client's major.minor version.
	ConditionScannerReady = "ScannerReady"
	// ConditionVulnerabilityDBReady reports on a gated target whether the
	// server DB is younger than maxDBAge.
	ConditionVulnerabilityDBReady = "VulnerabilityDBReady"
	// ConditionActive reports whether a VulnerabilityException applies.
	ConditionActive = "Active"
)

// Condition reasons.
const (
	ReasonReady                        = "Ready"
	ReasonSecretNotFound               = "SecretNotFound"
	ReasonInvalidSecret                = "InvalidSecret"
	ReasonTargetNotReady               = "TargetNotReady"
	ReasonProjectNotAllowed            = "ProjectNotAllowed"
	ReasonSourceNotAllowed             = "SourceNotAllowed"
	ReasonInvalidSpec                  = "InvalidSpec"
	ReasonTargetConflict               = "TargetConflict"
	ReasonSynced                       = "Synced"
	ReasonRescanned                    = "Rescanned"
	ReasonRescanFailed                 = "RescanFailed"
	ReasonTruncated                    = "Truncated"
	ReasonNoTagsSelected               = "NoTagsSelected"
	ReasonTagNotFound                  = "TagNotFound"
	ReasonSyncFailed                   = "SyncFailed"
	ReasonConfigRejected               = "ConfigRejected"
	ReasonCrashed                      = "Crashed"
	ReasonOwnershipConflict            = "OwnershipConflict"
	ReasonRepositoryOverrideNotAllowed = "RepositoryOverrideNotAllowed"
	ReasonAmbiguousAllowedSources      = "AmbiguousAllowedSources"
	ReasonScheduleTooFrequent          = "ScheduleTooFrequent"
	ReasonLimitExceeded                = "LimitExceeded"
	ReasonProjectReservedForAutoMirror = "ProjectReservedForAutoMirror"

	// Vulnerability gate.
	ReasonReported           = "Reported"
	ReasonBlocked            = "Blocked"
	ReasonClear              = "Clear"
	ReasonDBStale            = "DBStale"
	ReasonScannerUnavailable = "ScannerUnavailable"
	// ReasonNotConfigured: the gate is enabled but has no scanner URL, or
	// no client image and version.
	ReasonNotConfigured   = "NotConfigured"
	ReasonVersionMismatch = "VersionMismatch"
	ReasonScanFailed      = "ScanFailed"

	// VulnerabilityException.
	ReasonActive         = "Active"
	ReasonExpired        = "Expired"
	ReasonTooLong        = "TooLong"
	ReasonTargetNotFound = "TargetNotFound"
)

// CacheOptions limits the cache for the operator namespace types to that
// namespace, so the controller never lists them cluster-wide (threat model
// T14, T15).
func CacheOptions(namespace string) cache.Options {
	only := cache.ByObject{Namespaces: map[string]cache.Config{namespace: {}}}
	return cache.Options{ByObject: map[client.Object]cache.ByObject{
		&batchv1.CronJob{}:  only,
		&batchv1.Job{}:      only,
		&corev1.Pod{}:       only,
		&corev1.ConfigMap{}: only,
		&corev1.Secret{}:    only,
	}}
}
