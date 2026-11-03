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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Condition types.
const (
	// ConditionReady reports whether the resource is usable.
	ConditionReady = "Ready"
	// ConditionSynced reports the result of the last finished sync.
	ConditionSynced = "Synced"
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
	ReasonTruncated                    = "Truncated"
	ReasonSyncFailed                   = "SyncFailed"
	ReasonConfigRejected               = "ConfigRejected"
	ReasonCrashed                      = "Crashed"
	ReasonOwnershipConflict            = "OwnershipConflict"
	ReasonRepositoryOverrideNotAllowed = "RepositoryOverrideNotAllowed"
	ReasonAmbiguousAllowedSources      = "AmbiguousAllowedSources"
	ReasonScheduleTooFrequent          = "ScheduleTooFrequent"
	ReasonLimitExceeded                = "LimitExceeded"
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
