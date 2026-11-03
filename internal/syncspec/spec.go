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

// Package syncspec is the contract between the controller and the sync Job:
// the JSON spec the controller renders into a ConfigMap and the fixed paths
// where the Job finds its mounted files.
package syncspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
)

// Fixed paths and environment variables in the sync Job pod.
const (
	// SpecFile is the default location of the mounted spec.
	SpecFile = "/etc/tagwarden/spec.json"
	// TargetAuthFile is the target push credentials as a dockerconfigjson.
	TargetAuthFile = "/var/run/tagwarden/target/.dockerconfigjson"
	// TargetCAFile is an optional CA bundle for the target registry.
	TargetCAFile = "/var/run/tagwarden/target-ca/ca.crt"
	// ProxyCAFile is an optional CA bundle for a TLS-inspecting proxy.
	ProxyCAFile = "/var/run/tagwarden/proxy-ca/ca.crt"
	// ClientCertDir optionally holds tls.crt and tls.key for target mTLS.
	ClientCertDir = "/var/run/tagwarden/client-cert"

	// ProxyUserEnv and ProxyPasswordEnv hold the proxy credentials. The
	// proxy itself comes from HTTPS_PROXY and NO_PROXY. Only these
	// uppercase names are read; proxy credentials without HTTPS_PROXY,
	// for example next to a lowercase https_proxy, are a config error.
	ProxyUserEnv     = "TAGWARDEN_PROXY_USER"
	ProxyPasswordEnv = "TAGWARDEN_PROXY_PASSWORD" //nolint:gosec // env var name, not a credential
)

// Exit codes of the sync Job. 2 is not used: the Go runtime exits 2 on an
// unrecovered panic.
const (
	// ExitOK means every selected tag is on the target.
	ExitOK = 0
	// ExitSyncFailed means a tag failed, a mutation was refused or a
	// transient error stopped the run. The next run may succeed.
	ExitSyncFailed = 1
	// ExitConfig means the spec, the mounted files or the source checks
	// refused the run. It fails again until the configuration changes.
	ExitConfig = 3
)

// Mirror names the ArtifactMirror a sync runs for, for audit lines.
type Mirror struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Spec is one sync run.
type Spec struct {
	Mirror Mirror `json:"mirror"`
	// Source is registry/repository, with an explicit registry.
	Source string `json:"source"`
	// Target is registry/project/path.
	Target            string                 `json:"target"`
	Tags              tags.Policy            `json:"tags"`
	RequiredPlatforms []string               `json:"requiredPlatforms,omitempty"`
	OnTagMutation     v1alpha1.OnTagMutation `json:"onTagMutation"`
	// MaxTags caps the upstream listing. Zero means tags.MaxTags.
	MaxTags int `json:"maxTags,omitempty"`

	// AllowedSources are the registry hosts, as host[:port], that the
	// ClusterMirrorTarget allows. The Job re-checks Source against them.
	AllowedSources []string `json:"allowedSources"`
	// DeniedCIDRs are refused as source addresses on top of loopback,
	// link-local and metadata addresses, for example the cluster pod and
	// service CIDRs.
	DeniedCIDRs []string `json:"deniedCIDRs,omitempty"`

	// SourceRepo, TargetRepo and DeniedPrefixes are set by Decode.
	SourceRepo     name.Repository `json:"-"`
	TargetRepo     name.Repository `json:"-"`
	DeniedPrefixes []netip.Prefix  `json:"-"`
}

// Decode reads and validates a spec. Unknown fields are rejected, so a
// controller and Job of different versions fail loudly instead of silently
// dropping a field.
func Decode(r io.Reader) (Spec, error) {
	var s Spec
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("spec: %w", err)
	}
	if d.More() {
		return Spec{}, errors.New("spec: trailing data after the JSON object")
	}
	if err := s.validate(); err != nil {
		return Spec{}, fmt.Errorf("spec: %w", err)
	}
	return s, nil
}

func (s *Spec) validate() error {
	if s.Mirror.Namespace == "" || s.Mirror.Name == "" {
		return errors.New("mirror namespace and name are required")
	}
	var err error
	if s.SourceRepo, err = name.NewRepository(s.Source, name.StrictValidation); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if s.TargetRepo, err = name.NewRepository(s.Target, name.StrictValidation); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if _, err := tags.Select(nil, s.Tags); err != nil {
		return fmt.Errorf("tags: %w", err)
	}
	for _, p := range s.RequiredPlatforms {
		if _, err := v1.ParsePlatform(p); err != nil {
			return fmt.Errorf("requiredPlatforms: %q: %w", p, err)
		}
	}
	switch s.OnTagMutation {
	case v1alpha1.OnTagMutationFail, v1alpha1.OnTagMutationOverwrite, v1alpha1.OnTagMutationIgnore:
	default:
		return fmt.Errorf("onTagMutation: unknown value %q", s.OnTagMutation)
	}
	if s.MaxTags < 0 {
		return errors.New("maxTags: must not be negative")
	}
	if len(s.AllowedSources) == 0 || slices.Contains(s.AllowedSources, "") {
		return errors.New("allowedSources: at least one non-empty host is required")
	}
	for _, c := range s.DeniedCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("deniedCIDRs: %w", err)
		}
		s.DeniedPrefixes = append(s.DeniedPrefixes, p)
	}
	return nil
}
