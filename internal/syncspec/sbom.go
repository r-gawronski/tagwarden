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

package syncspec

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/sbom"
)

// Environment of a sidecar that generates SBOMs. TAGWARDEN_JAVA_DB
// (ScannerJavaDBEnv) selects the Java DB mode for both request kinds.
const (
	SBOMTimeoutEnv = "TAGWARDEN_SBOM_TIMEOUT" // a Go duration, for example 10m0s
)

// SBOM failure reasons, as in Report.SBOMFailures.
const (
	SBOMGenerationFailed = "GenerationFailed"
	SBOMTooLarge         = "TooLarge"
	SBOMAttachFailed     = "AttachFailed"
	SBOMSigningFailed    = "SigningFailed"
	SBOMMissing          = "Missing"
)

// MaxSBOMFailures caps Report.SBOMFailures.
const MaxSBOMFailures = 10

// SBOM is the SBOM policy of an image mirror, resolved by the controller
// from its ClusterMirrorTarget. Without it the Job attaches no SBOM.
type SBOM struct {
	// Mode is PreferUpstream or Generate; the controller leaves SBOM unset
	// for Disabled.
	Mode     v1alpha1.SBOMMode   `json:"mode"`
	Format   v1alpha1.SBOMFormat `json:"format"`
	Required bool                `json:"required,omitempty"`
	// Generator is the sidecar that generates SBOMs. A gated Job runs one
	// sidecar for both, so its version and Java DB equal Gate.Scanner's.
	Generator SBOMGenerator `json:"generator"`
}

// SBOMGenerator is the pinned Trivy sidecar that generates SBOMs.
type SBOMGenerator struct {
	// Version is the Trivy version pinned with Image. The sidecar must
	// report the same major.minor.
	Version string `json:"version"`
	// Image is the generator image, for the audit line only.
	Image string `json:"image,omitempty"`
	// Timeout is the generation timeout of one platform child.
	Timeout metav1.Duration     `json:"timeout"`
	JavaDB  v1alpha1.JavaDBMode `json:"javaDB"`
	// JavaDBRepository is <registry>/<repository>:<tag> in the target
	// registry, required with JavaDB PerJob.
	JavaDBRepository string `json:"javaDBRepository,omitempty"`
}

// SBOMFailure is a tag whose SBOM could not be produced or attached for
// every platform child. Published means the tag is on the target with
// that digest after the run.
type SBOMFailure struct {
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
	Reason    string `json:"reason"`
	Published bool   `json:"published,omitempty"`
}

func (s *SBOM) validate(target name.Repository, gate *Gate) error {
	if s.Mode != v1alpha1.SBOMModePreferUpstream && s.Mode != v1alpha1.SBOMModeGenerate {
		return fmt.Errorf("mode: unknown value %q", s.Mode)
	}
	if !sbom.Format(s.Format).Valid() {
		return fmt.Errorf("format: unknown value %q", s.Format)
	}
	g := s.Generator
	if !versionPattern.MatchString(g.Version) {
		return errors.New("generator.version: must be <major>.<minor>.<patch>")
	}
	if g.Timeout.Duration <= 0 || g.Timeout.Duration > time.Hour {
		return errors.New("generator.timeout: must be positive and at most 1h")
	}
	if err := validateJavaDB(g.JavaDB, g.JavaDBRepository, target); err != nil {
		return fmt.Errorf("generator.%w", err)
	}
	if gate != nil {
		sc := gate.Scanner
		if g.Version != sc.Version || g.JavaDB != sc.JavaDB || g.JavaDBRepository != sc.JavaDBRepository ||
			g.Image != "" && sc.Image != "" && g.Image != sc.Image {
			return errors.New("generator: must equal gate.scanner, a gated Job runs one sidecar for both")
		}
	}
	return nil
}

func validateJavaDB(mode v1alpha1.JavaDBMode, repo string, target name.Repository) error {
	switch mode {
	case v1alpha1.JavaDBDisabled:
	case v1alpha1.JavaDBPerJob:
		ref, err := name.NewTag(repo, name.StrictValidation)
		if err != nil {
			return fmt.Errorf("javaDBRepository: %w", err)
		}
		if CanonicalRegistry(ref.RegistryStr()) != CanonicalRegistry(target.RegistryStr()) {
			return errors.New("javaDBRepository: must be in the target registry")
		}
	default:
		return fmt.Errorf("javaDB: unknown value %q", mode)
	}
	return nil
}

var sbomReasons = []string{SBOMGenerationFailed, SBOMTooLarge, SBOMAttachFailed, SBOMSigningFailed, SBOMMissing}

func validateSBOMFields(r Report) error {
	if min(r.SBOMGenerated, r.SBOMUpstream, r.SBOMFailed) < 0 {
		return errors.New("report: negative count")
	}
	if r.V == ReportVersion && (r.SBOMGenerated+r.SBOMUpstream+r.SBOMFailed > 0 || len(r.SBOMFailures) > 0) {
		return errors.New("report: SBOM fields in version 1")
	}
	if len(r.SBOMFailures) > MaxSBOMFailures {
		return errors.New("report: too many SBOM failures")
	}
	for _, f := range r.SBOMFailures {
		if !tagPattern.MatchString(f.Tag) || !digestPattern.MatchString(f.Digest) || !slices.Contains(sbomReasons, f.Reason) {
			return errors.New("report: invalid SBOM failure")
		}
	}
	return nil
}
