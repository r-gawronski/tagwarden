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

// Package sbom checks SBOM documents and builds the OCI 1.1 referrers that
// attach them to mirrored images (docs/design/sbom.md). It does no I/O
// beyond the readers it is given.
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Format is an SBOM format. Documents are always JSON.
type Format string

// SBOM formats, as in ClusterMirrorTarget spec.sbom.format.
const (
	CycloneDX Format = "CycloneDX"
	SPDX      Format = "SPDX"
)

// Valid reports whether f is a known format.
func (f Format) Valid() bool { return f == CycloneDX || f == SPDX }

// MediaType is the layer media type and artifactType of a document of
// format f, or "" for an unknown format.
func (f Format) MediaType() types.MediaType {
	switch f {
	case CycloneDX:
		return "application/vnd.cyclonedx+json"
	case SPDX:
		return "application/spdx+json"
	}
	return ""
}

// TrivyFormat is the trivy --format value for f, or "" for an unknown
// format. It is also the suffix of a generation request file.
func (f Format) TrivyFormat() string {
	switch f {
	case CycloneDX:
		return "cyclonedx"
	case SPDX:
		return "spdx-json"
	}
	return ""
}

// MaxSize caps one SBOM document. It bounds the sync container's memory and
// the scan volume.
const MaxSize int64 = 64 << 20

// Annotations on generated referrers. Upstream referrers that carry any
// key under AnnotationPrefix are not copied, so only Tagwarden can claim a
// referrer as its own.
const (
	AnnotationPrefix = "dev.tagwarden."
	// AnnotationGenerator names the generator and its version, for
	// example trivy/0.76.1. It marks a generated SBOM.
	AnnotationGenerator = AnnotationPrefix + "sbom.generator"
	// AnnotationFormat names the Format. Some registries list a referrer
	// with its config media type as artifactType, so the format cannot be
	// read from the referrers index alone.
	AnnotationFormat = AnnotationPrefix + "sbom.format"
	// AnnotationPlatform names the platform of an index-level copy.
	AnnotationPlatform = AnnotationPrefix + "sbom.platform"
	// AnnotationJavaScanned is "false" when JAR files were skipped.
	AnnotationJavaScanned = AnnotationPrefix + "sbom.java-scanned"

	annotationCreated = "org.opencontainers.image.created"
)

// EmptyConfigMediaType is the OCI 1.1 empty descriptor media type; its
// content is {}.
const EmptyConfigMediaType = "application/vnd.oci.empty.v1+json"

var emptyConfig = []byte("{}")

// Errors of Check.
var (
	ErrTooLarge = errors.New("sbom: document too large")
	ErrInvalid  = errors.New("sbom: invalid document")
)

var (
	cdxVersion  = regexp.MustCompile(`^1\.[0-9]{1,3}$`)
	spdxVersion = regexp.MustCompile(`^SPDX-2\.[0-9]{1,3}$`)
	generator   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?/[0-9]+\.[0-9]+\.[0-9]+$`)
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Check reads a document of format f from r and returns its bytes
// unchanged. The input is untrusted: it must be at most limit bytes
// (MaxSize when limit is not in (0, MaxSize]), valid UTF-8 and exactly one
// JSON object with unique top-level keys and the markers of the format:
// bomFormat CycloneDX and specVersion 1.<n>, or spdxVersion SPDX-2.<n> and
// SPDXID SPDXRef-DOCUMENT.
func Check(r io.Reader, f Format, limit int64) ([]byte, error) {
	if limit <= 0 || limit > MaxSize {
		limit = MaxSize
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("sbom: read: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, limit)
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrInvalid)
	}
	top, err := topLevel(b)
	if err != nil {
		return nil, err
	}
	str := func(k string) string {
		var s string
		if v, ok := top[k]; ok && json.Unmarshal(v, &s) == nil {
			return s
		}
		return ""
	}
	switch f {
	case CycloneDX:
		if str("bomFormat") != "CycloneDX" || !cdxVersion.MatchString(str("specVersion")) {
			return nil, fmt.Errorf("%w: not a CycloneDX 1.x document", ErrInvalid)
		}
	case SPDX:
		if !spdxVersion.MatchString(str("spdxVersion")) || str("SPDXID") != "SPDXRef-DOCUMENT" {
			return nil, fmt.Errorf("%w: not an SPDX 2.x document", ErrInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: unknown format %q", ErrInvalid, f)
	}
	return b, nil
}

// topLevel parses b as one JSON object and returns its top-level members.
// A duplicate key is refused: readers differ on which value wins.
func topLevel(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("%w: not a JSON object", ErrInvalid)
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: not valid JSON", ErrInvalid)
		}
		k, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("%w: not valid JSON", ErrInvalid)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrInvalid, k)
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: not valid JSON", ErrInvalid)
		}
		out[k] = v
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, fmt.Errorf("%w: not valid JSON", ErrInvalid)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return out, nil
}

// Referrer is a generated SBOM to attach to Subject.
type Referrer struct {
	Format   Format
	Document []byte
	// Subject is the described manifest: a platform child, or the index
	// for an index-level copy.
	Subject v1.Descriptor
	// Generator is name/version, for example trivy/0.76.1.
	Generator string
	// Platform is set on an index-level copy only.
	Platform string
	// JavaScanned is false when JAR files were skipped.
	JavaScanned bool
	Created     time.Time
}

func (r Referrer) validate() error {
	if !r.Format.Valid() {
		return fmt.Errorf("unknown format %q", r.Format)
	}
	if len(r.Document) == 0 || int64(len(r.Document)) > MaxSize {
		return errors.New("document empty or too large")
	}
	s := r.Subject
	if s.Digest.Algorithm != "sha256" || !hexDigest.MatchString(s.Digest.Hex) || s.Size <= 0 ||
		!s.MediaType.IsImage() && !s.MediaType.IsIndex() {
		return errors.New("subject must be a sha256 image manifest or index descriptor")
	}
	if !generator.MatchString(r.Generator) {
		return fmt.Errorf("generator %q must be name/x.y.z", r.Generator)
	}
	if r.Platform != "" {
		if _, err := v1.ParsePlatform(r.Platform); err != nil {
			return fmt.Errorf("platform: %w", err)
		}
	}
	if r.Created.IsZero() {
		return errors.New("created is required")
	}
	return nil
}

// Image returns the OCI 1.1 referrer manifest for r, with the empty config
// and the document as its only layer, ready for remote.Write. The same
// inputs give the same digest.
func (r Referrer) Image() (v1.Image, error) {
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("sbom: referrer: %w", err)
	}
	mt := r.Format.MediaType()
	layer := static.NewLayer(r.Document, mt)
	ld, err := partial.Descriptor(layer)
	if err != nil {
		return nil, err
	}
	cfg, _, err := v1.SHA256(bytes.NewReader(emptyConfig))
	if err != nil {
		return nil, err
	}
	ann := map[string]string{
		annotationCreated:   r.Created.UTC().Format(time.RFC3339),
		AnnotationGenerator: r.Generator,
		AnnotationFormat:    string(r.Format),
	}
	if r.Platform != "" {
		ann[AnnotationPlatform] = r.Platform
	}
	if !r.JavaScanned {
		ann[AnnotationJavaScanned] = "false"
	}
	subject := v1.Descriptor{MediaType: r.Subject.MediaType, Digest: r.Subject.Digest, Size: r.Subject.Size}
	raw, err := json.Marshal(v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  string(mt),
		Config:        v1.Descriptor{MediaType: EmptyConfigMediaType, Digest: cfg, Size: int64(len(emptyConfig))},
		Layers:        []v1.Descriptor{{MediaType: mt, Digest: ld.Digest, Size: ld.Size}},
		Subject:       &subject,
		Annotations:   ann,
	})
	if err != nil {
		return nil, err
	}
	return partial.CompressedToImage(&referrerImage{raw: raw, layer: layer, digest: ld.Digest})
}

type referrerImage struct {
	raw    []byte
	layer  v1.Layer
	digest v1.Hash
}

func (i *referrerImage) RawConfigFile() ([]byte, error)      { return emptyConfig, nil }
func (i *referrerImage) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }
func (i *referrerImage) RawManifest() ([]byte, error)        { return i.raw, nil }

func (i *referrerImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if h != i.digest {
		return nil, fmt.Errorf("sbom: referrer has no layer %s", h)
	}
	return i.layer, nil
}

// Upstream checks an upstream referrer manifest as an SBOM of format f for
// subject: an OCI image manifest whose subject is subject, whose
// artifactType (or, without one, config media type) is the format's media
// type, with exactly one layer of that type and no annotation under
// AnnotationPrefix. It returns the layer to fetch and pass to Check.
func Upstream(raw []byte, subject v1.Hash, f Format) (v1.Descriptor, error) {
	if !f.Valid() {
		return v1.Descriptor{}, fmt.Errorf("sbom: unknown format %q", f)
	}
	var m v1.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return v1.Descriptor{}, errors.New("sbom: upstream referrer is not valid JSON")
	}
	mt := f.MediaType()
	at := m.ArtifactType
	if at == "" {
		at = string(m.Config.MediaType)
	}
	switch {
	case m.MediaType != types.OCIManifestSchema1:
		return v1.Descriptor{}, errors.New("sbom: upstream referrer is not an OCI image manifest")
	case m.Subject == nil || m.Subject.Digest != subject:
		return v1.Descriptor{}, errors.New("sbom: upstream referrer has another subject")
	case at != string(mt):
		return v1.Descriptor{}, fmt.Errorf("sbom: upstream referrer is not %s", f)
	case len(m.Layers) != 1 || m.Layers[0].MediaType != mt:
		return v1.Descriptor{}, fmt.Errorf("sbom: upstream referrer needs exactly one %s layer", mt)
	case Reserved(m.Annotations):
		return v1.Descriptor{}, errors.New("sbom: upstream referrer claims Tagwarden annotations")
	}
	return m.Layers[0], nil
}

// Reserved reports whether ann has a key under AnnotationPrefix, compared
// without case.
func Reserved(ann map[string]string) bool {
	for k := range ann {
		if strings.HasPrefix(strings.ToLower(k), AnnotationPrefix) {
			return true
		}
	}
	return false
}

// Generated reports whether d, an entry of a target referrers index, is an
// SBOM of format f that Tagwarden generated: an image manifest with a
// generator annotation and the format annotation f. Its artifactType must
// be the format's media type, or the empty config media type for
// registries that list the config media type instead. platform is "" for
// the referrer of a platform child and the platform for an index-level
// copy. Upstream referrers with Tagwarden annotations are never copied, so
// the annotations identify generated referrers on the target.
func Generated(d v1.Descriptor, f Format, platform string) bool {
	return f.Valid() && d.MediaType.IsImage() &&
		(d.ArtifactType == string(f.MediaType()) || d.ArtifactType == EmptyConfigMediaType) &&
		d.Annotations[AnnotationGenerator] != "" && d.Annotations[AnnotationFormat] == string(f) &&
		d.Annotations[AnnotationPlatform] == platform
}
