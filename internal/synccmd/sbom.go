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

package synccmd

import (
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/sbom"
	"github.com/r-gawronski/tagwarden/internal/sync"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// newSBOM maps the SBOM policy of the spec onto the sync request.
func newSBOM(spec syncspec.Spec, p options) (*sync.SBOM, error) {
	s := spec.SBOM
	out := &sync.SBOM{
		Mode: s.Mode, Format: sbom.Format(s.Format), Required: s.Required,
		Version: s.Generator.Version, Timeout: s.Generator.Timeout.Duration,
		LayoutDir: p.layoutDir, ScanDir: p.scanDir,
	}
	if s.Generator.JavaDB == v1alpha1.JavaDBPerJob {
		tag, err := name.NewTag(s.Generator.JavaDBRepository, name.StrictValidation)
		if err != nil {
			return nil, err
		}
		out.JavaDB = &tag
	}
	return out, nil
}

// sbomSummary adds the version 2 SBOM fields of a run with an SBOM policy
// to r. A failure entry is published when the tag is on the target with
// that digest after the run.
func sbomSummary(r *report, res sync.Result) {
	r.V = syncspec.ReportVersionGate
	if r.JavaScanned == nil {
		r.JavaScanned = &res.JavaScanned
	}
	type entry struct {
		a         sync.Artifact
		published bool
	}
	byTag := map[string]entry{}
	for _, l := range []struct {
		as        []sync.Artifact
		published bool
	}{{res.Copied, true}, {res.Skipped, true}, {res.Failed, false}} {
		for _, a := range l.as {
			if a.SBOM != nil {
				byTag[a.Tag] = entry{a, l.published}
			}
		}
	}
	for _, tag := range res.Selected {
		e, ok := byTag[tag]
		if !ok {
			continue
		}
		for _, p := range e.a.SBOM.Platforms {
			switch p.Source {
			case sync.SBOMSourceGenerated:
				r.SBOMGenerated++
			case sync.SBOMSourceUpstream:
				r.SBOMUpstream++
			}
		}
		if e.a.SBOM.Reason == "" {
			continue
		}
		r.SBOMFailed++
		if len(r.SBOMFailures) < syncspec.MaxSBOMFailures {
			r.SBOMFailures = append(r.SBOMFailures, syncspec.SBOMFailure{
				Tag: tag, Digest: e.a.Digest, Reason: e.a.SBOM.Reason, Published: e.published,
			})
		}
	}
}

type auditSBOM struct {
	Mode      string              `json:"mode"`
	Format    string              `json:"format"`
	Required  bool                `json:"required"`
	Generator auditGenerator      `json:"generator"`
	Platforms []auditSBOMPlatform `json:"platforms,omitempty"`
	Failure   string              `json:"failure,omitempty"`
	Detail    string              `json:"detail,omitempty"`
}

type auditGenerator struct {
	Version string `json:"version"`
	Image   string `json:"image,omitempty"`
}

type auditSBOMPlatform struct {
	Platform    string `json:"platform,omitempty"`
	Digest      string `json:"digest"`
	Source      string `json:"source"`
	Referrer    string `json:"referrer,omitempty"`
	Size        int64  `json:"size,omitempty"`
	JavaScanned bool   `json:"javaScanned"`
}

// newAuditSBOM is the SBOM detail of a tag for the audit line.
func newAuditSBOM(s *syncspec.SBOM, r *sync.SBOMResult) *auditSBOM {
	if s == nil || r == nil {
		return nil
	}
	a := &auditSBOM{
		Mode: string(s.Mode), Format: string(s.Format), Required: s.Required,
		Generator: auditGenerator{Version: s.Generator.Version, Image: s.Generator.Image},
		Failure:   r.Reason, Detail: r.Detail,
	}
	for _, p := range r.Platforms {
		a.Platforms = append(a.Platforms, auditSBOMPlatform(p))
	}
	return a
}
