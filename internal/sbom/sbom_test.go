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

package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	cdxDoc  = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	spdxDoc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}`
	gen     = "trivy/0.76.1"
	amd64   = "linux/amd64"
)

var (
	created = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	child   = v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)},
		Size:      1234,
	}
)

func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		f     Format
		valid bool
		mt    types.MediaType
		trivy string
	}{
		{CycloneDX, true, "application/vnd.cyclonedx+json", "cyclonedx"},
		{SPDX, true, "application/spdx+json", "spdx-json"},
		{"cyclonedx", false, "", ""},
		{"", false, "", ""},
	} {
		if got := tc.f.Valid(); got != tc.valid {
			t.Errorf("%q.Valid() = %v, want %v", tc.f, got, tc.valid)
		}
		if got := tc.f.MediaType(); got != tc.mt {
			t.Errorf("%q.MediaType() = %q, want %q", tc.f, got, tc.mt)
		}
		if got := tc.f.TrivyFormat(); got != tc.trivy {
			t.Errorf("%q.TrivyFormat() = %q, want %q", tc.f, got, tc.trivy)
		}
	}
}

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name  string
		f     Format
		in    string
		limit int64
		err   error
	}{
		{name: "cyclonedx", f: CycloneDX, in: cdxDoc},
		{name: "cyclonedx 1.10", f: CycloneDX, in: `{"bomFormat":"CycloneDX","specVersion":"1.10"}`},
		{name: "spdx", f: SPDX, in: spdxDoc},
		{name: "spdx 2.2 with whitespace", f: SPDX, in: " \n{\"spdxVersion\":\"SPDX-2.2\",\"SPDXID\":\"SPDXRef-DOCUMENT\"}\n"},
		{name: "wrong format", f: SPDX, in: cdxDoc, err: ErrInvalid},
		{name: "other way round", f: CycloneDX, in: spdxDoc, err: ErrInvalid},
		{name: "cyclonedx 2.0", f: CycloneDX, in: `{"bomFormat":"CycloneDX","specVersion":"2.0"}`, err: ErrInvalid},
		{name: "cyclonedx number version", f: CycloneDX, in: `{"bomFormat":"CycloneDX","specVersion":1.6}`, err: ErrInvalid},
		{name: "cyclonedx lower case", f: CycloneDX, in: `{"bomFormat":"cyclonedx","specVersion":"1.6"}`, err: ErrInvalid},
		{name: "spdx 3", f: SPDX, in: `{"spdxVersion":"SPDX-3.0","SPDXID":"SPDXRef-DOCUMENT"}`, err: ErrInvalid},
		{name: "spdx wrong id", f: SPDX, in: `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-x"}`, err: ErrInvalid},
		{name: "duplicate key", f: CycloneDX, in: `{"bomFormat":"CycloneDX","specVersion":"1.6","bomFormat":"x"}`, err: ErrInvalid},
		{name: "array", f: CycloneDX, in: `[` + cdxDoc + `]`, err: ErrInvalid},
		{name: "trailing data", f: CycloneDX, in: cdxDoc + `{}`, err: ErrInvalid},
		{name: "trailing garbage", f: CycloneDX, in: cdxDoc + `x`, err: ErrInvalid},
		{name: "truncated", f: CycloneDX, in: cdxDoc[:20], err: ErrInvalid},
		{name: "empty", f: CycloneDX, in: "", err: ErrInvalid},
		{name: "invalid utf-8", f: CycloneDX, in: `{"bomFormat":"CycloneDX","specVersion":"1.6","x":"` + "\xff" + `"}`, err: ErrInvalid},
		{name: "gzip magic", f: CycloneDX, in: "\x1f\x8b\x08\x00", err: ErrInvalid},
		{name: "unknown format", f: "x", in: cdxDoc, err: ErrInvalid},
		{name: "at the limit", f: CycloneDX, in: cdxDoc, limit: int64(len(cdxDoc))},
		{name: "over the limit", f: CycloneDX, in: cdxDoc, limit: int64(len(cdxDoc)) - 1, err: ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Check(strings.NewReader(tc.in), tc.f, tc.limit)
			if !errors.Is(err, tc.err) {
				t.Fatalf("Check() error = %v, want %v", err, tc.err)
			}
			if err == nil && string(b) != tc.in {
				t.Errorf("Check() = %q, want the input unchanged", b)
			}
		})
	}
}

func TestCheckCapsAtMaxSize(t *testing.T) {
	big := `{"bomFormat":"CycloneDX","specVersion":"1.6","x":"` + strings.Repeat("a", int(MaxSize)) + `"}`
	for _, limit := range []int64{0, -1, MaxSize + 1} {
		if _, err := Check(strings.NewReader(big), CycloneDX, limit); !errors.Is(err, ErrTooLarge) {
			t.Errorf("Check(limit %d) error = %v, want ErrTooLarge", limit, err)
		}
	}
}

func FuzzCheck(f *testing.F) {
	f.Add(cdxDoc, true)
	f.Add(spdxDoc, false)
	f.Add(`{"bomFormat":"CycloneDX"`, true)
	f.Fuzz(func(t *testing.T, in string, cdx bool) {
		format := SPDX
		if cdx {
			format = CycloneDX
		}
		b, err := Check(strings.NewReader(in), format, 1<<16)
		if err != nil {
			return
		}
		if string(b) != in || !json.Valid(b) {
			t.Fatalf("Check() accepted %q", in)
		}
	})
}

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     types.MediaType   `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        v1.Descriptor     `json:"config"`
	Layers        []v1.Descriptor   `json:"layers"`
	Subject       *v1.Descriptor    `json:"subject"`
	Annotations   map[string]string `json:"annotations"`
}

func TestReferrerImage(t *testing.T) {
	r := Referrer{Format: CycloneDX, Document: []byte(cdxDoc), Subject: child, Generator: gen, Created: created}
	img, err := r.Image()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	docHash, _, _ := v1.SHA256(strings.NewReader(cdxDoc))
	if m.SchemaVersion != 2 || m.MediaType != types.OCIManifestSchema1 || m.ArtifactType != "application/vnd.cyclonedx+json" {
		t.Errorf("manifest header = %d %q %q", m.SchemaVersion, m.MediaType, m.ArtifactType)
	}
	if m.Config.MediaType != EmptyConfigMediaType || m.Config.Size != 2 ||
		m.Config.Digest.String() != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Errorf("config = %+v, want the OCI empty descriptor", m.Config)
	}
	if len(m.Layers) != 1 || m.Layers[0].MediaType != "application/vnd.cyclonedx+json" ||
		m.Layers[0].Digest != docHash || m.Layers[0].Size != int64(len(cdxDoc)) {
		t.Errorf("layers = %+v", m.Layers)
	}
	if m.Subject == nil || m.Subject.Digest != child.Digest || m.Subject.Size != child.Size || m.Subject.MediaType != child.MediaType {
		t.Errorf("subject = %+v, want %+v", m.Subject, child)
	}
	want := map[string]string{
		"org.opencontainers.image.created": "2026-11-04T12:00:00Z",
		AnnotationGenerator:                gen,
		AnnotationFormat:                   "CycloneDX",
		AnnotationJavaScanned:              "false",
	}
	if !equalMaps(m.Annotations, want) {
		t.Errorf("annotations = %v, want %v", m.Annotations, want)
	}

	// The pushed bytes: config, layer and digests line up.
	cfg, err := img.RawConfigFile()
	if err != nil || string(cfg) != "{}" {
		t.Errorf("RawConfigFile() = %q, %v", cfg, err)
	}
	l, err := img.LayerByDigest(docHash)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := l.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(rc)
	if buf.String() != cdxDoc {
		t.Errorf("layer = %q", buf.String())
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if h, _, _ := v1.SHA256(bytes.NewReader(raw)); h != d {
		t.Errorf("Digest() = %s, want %s", d, h)
	}

	// Deterministic: the same inputs give the same digest.
	again, _ := r.Image()
	if d2, _ := again.Digest(); d2 != d {
		t.Errorf("second Digest() = %s, want %s", d2, d)
	}
}

func TestReferrerImageOptions(t *testing.T) {
	r := Referrer{Format: SPDX, Document: []byte(spdxDoc), Subject: child, Generator: gen,
		Platform: amd64, JavaScanned: true, Created: created.In(time.FixedZone("x", 3600))}
	img, err := r.Image()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := img.RawManifest()
	var m manifest
	_ = json.Unmarshal(raw, &m)
	want := map[string]string{
		"org.opencontainers.image.created": "2026-11-04T12:00:00Z",
		AnnotationGenerator:                gen,
		AnnotationFormat:                   "SPDX",
		AnnotationPlatform:                 amd64,
	}
	if m.ArtifactType != "application/spdx+json" || !equalMaps(m.Annotations, want) {
		t.Errorf("artifactType %q, annotations %v, want %v", m.ArtifactType, m.Annotations, want)
	}
}

func TestReferrerImageRejects(t *testing.T) {
	ok := Referrer{Format: CycloneDX, Document: []byte(cdxDoc), Subject: child, Generator: gen, Created: created}
	for name, mod := range map[string]func(*Referrer){
		"format":            func(r *Referrer) { r.Format = "x" },
		"empty document":    func(r *Referrer) { r.Document = nil },
		"document too big":  func(r *Referrer) { r.Document = make([]byte, MaxSize+1) },
		"subject algorithm": func(r *Referrer) { r.Subject.Digest.Algorithm = "sha512" },
		"subject hex":       func(r *Referrer) { r.Subject.Digest.Hex = "AA" },
		"subject size":      func(r *Referrer) { r.Subject.Size = 0 },
		"subject type":      func(r *Referrer) { r.Subject.MediaType = "application/vnd.cyclonedx+json" },
		"generator":         func(r *Referrer) { r.Generator = "trivy 0.76.1" },
		"no generator":      func(r *Referrer) { r.Generator = "" },
		"platform":          func(r *Referrer) { r.Platform = "linux/amd64/v1/x" },
		"created":           func(r *Referrer) { r.Created = time.Time{} },
	} {
		r := ok
		mod(&r)
		if _, err := r.Image(); err == nil {
			t.Errorf("%s: Image() accepted %+v", name, r)
		}
	}
	idx := ok
	idx.Subject.MediaType = types.OCIImageIndex
	if _, err := idx.Image(); err != nil {
		t.Errorf("index subject: %v", err)
	}
}

func upstreamManifest(mod func(m map[string]any)) []byte {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     string(types.OCIManifestSchema1),
		"artifactType":  "application/vnd.cyclonedx+json",
		"config":        map[string]any{"mediaType": EmptyConfigMediaType, "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
		"layers": []any{map[string]any{"mediaType": "application/vnd.cyclonedx+json",
			"digest": "sha256:" + strings.Repeat("b", 64), "size": 10}},
		"subject": map[string]any{"mediaType": string(types.OCIManifestSchema1), "digest": child.Digest.String(), "size": child.Size},
	}
	if mod != nil {
		mod(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestUpstream(t *testing.T) {
	layer := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		name string
		f    Format
		raw  []byte
		ok   bool
	}{
		{"cyclonedx referrer", CycloneDX, upstreamManifest(nil), true},
		{"config media type without artifactType", CycloneDX, upstreamManifest(func(m map[string]any) {
			delete(m, "artifactType")
			m["config"] = map[string]any{"mediaType": "application/vnd.cyclonedx+json", "digest": layer, "size": 10}
		}), true},
		{"other annotations", CycloneDX, upstreamManifest(func(m map[string]any) {
			m["annotations"] = map[string]string{"org.opencontainers.image.created": "x"}
		}), true},
		{"wrong format", SPDX, upstreamManifest(nil), false},
		{"wrong subject", CycloneDX, upstreamManifest(func(m map[string]any) {
			m["subject"] = map[string]any{"mediaType": string(types.OCIManifestSchema1), "digest": "sha256:" + strings.Repeat("c", 64), "size": 1}
		}), false},
		{"no subject", CycloneDX, upstreamManifest(func(m map[string]any) { delete(m, "subject") }), false},
		{"index", CycloneDX, upstreamManifest(func(m map[string]any) { m["mediaType"] = string(types.OCIImageIndex) }), false},
		{"docker manifest", CycloneDX, upstreamManifest(func(m map[string]any) { m["mediaType"] = string(types.DockerManifestSchema2) }), false},
		{"two layers", CycloneDX, upstreamManifest(func(m map[string]any) {
			l := m["layers"].([]any)
			m["layers"] = append(l, l[0])
		}), false},
		{"no layers", CycloneDX, upstreamManifest(func(m map[string]any) { m["layers"] = []any{} }), false},
		{"layer of another type", CycloneDX, upstreamManifest(func(m map[string]any) {
			m["layers"] = []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer, "size": 10}}
		}), false},
		{"artifactType differs from config", CycloneDX, upstreamManifest(func(m map[string]any) { m["artifactType"] = "application/vnd.in-toto+json" }), false},
		{"reserved annotation", CycloneDX, upstreamManifest(func(m map[string]any) {
			m["annotations"] = map[string]string{AnnotationGenerator: gen}
		}), false},
		{"reserved annotation, other key", CycloneDX, upstreamManifest(func(m map[string]any) {
			m["annotations"] = map[string]string{"dev.tagwarden.anything": "x"}
		}), false},
		{"not json", CycloneDX, []byte("{"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Upstream(tc.raw, child.Digest, tc.f)
			if (err == nil) != tc.ok {
				t.Fatalf("Upstream() error = %v, want ok %v", err, tc.ok)
			}
			if tc.ok && d.Digest.String() != layer {
				t.Errorf("Upstream() layer = %s, want %s", d.Digest, layer)
			}
		})
	}
}

func TestUpstreamOfGenerated(t *testing.T) {
	// A Tagwarden referrer copied upstream must not count as upstream.
	img, _ := Referrer{Format: CycloneDX, Document: []byte(cdxDoc), Subject: child, Generator: gen, Created: created}.Image()
	raw, _ := img.RawManifest()
	if _, err := Upstream(raw, child.Digest, CycloneDX); err == nil {
		t.Error("Upstream() accepted a Tagwarden-generated referrer")
	}
}

func TestReserved(t *testing.T) {
	for _, tc := range []struct {
		ann  map[string]string
		want bool
	}{
		{nil, false},
		{map[string]string{"org.opencontainers.image.created": "x"}, false},
		{map[string]string{"dev.tagwardenx.y": "x"}, false},
		{map[string]string{"tagwarden.dev/x": "x"}, false},
		{map[string]string{AnnotationGenerator: "x"}, true},
		{map[string]string{"DEV.TAGWARDEN.X": "x"}, true},
	} {
		if got := Reserved(tc.ann); got != tc.want {
			t.Errorf("Reserved(%v) = %v, want %v", tc.ann, got, tc.want)
		}
	}
}

func TestGenerated(t *testing.T) {
	cdx := "application/vnd.cyclonedx+json"
	ann := func(kv ...string) map[string]string {
		m := map[string]string{AnnotationGenerator: gen, AnnotationFormat: "CycloneDX"}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "" {
				delete(m, kv[i])
				continue
			}
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	ref := func(at string, a map[string]string) v1.Descriptor {
		return v1.Descriptor{MediaType: types.OCIManifestSchema1, ArtifactType: at, Annotations: a}
	}
	for _, tc := range []struct {
		name     string
		d        v1.Descriptor
		f        Format
		platform string
		want     bool
	}{
		{"child", ref(cdx, ann()), CycloneDX, "", true},
		{"registry lists the config media type", ref(EmptyConfigMediaType, ann()), CycloneDX, "", true},
		{"other artifactType", ref("application/vnd.in-toto+json", ann()), CycloneDX, "", false},
		{"index copy", ref(cdx, ann(AnnotationPlatform, amd64)), CycloneDX, amd64, true},
		{"index copy for another platform", ref(cdx, ann(AnnotationPlatform, amd64)), CycloneDX, "linux/arm64", false},
		{"index copy looked up as child", ref(cdx, ann(AnnotationPlatform, amd64)), CycloneDX, "", false},
		{"child looked up as index copy", ref(cdx, ann()), CycloneDX, amd64, false},
		{"upstream", ref(cdx, nil), CycloneDX, "", false},
		{"other format", ref(cdx, ann()), SPDX, "", false},
		{"format annotation missing", ref(cdx, ann(AnnotationFormat, "")), CycloneDX, "", false},
		{"generator missing", ref(cdx, ann(AnnotationGenerator, "")), CycloneDX, "", false},
		{"index media type", v1.Descriptor{MediaType: types.OCIImageIndex, ArtifactType: cdx, Annotations: ann()}, CycloneDX, "", false},
	} {
		if got := Generated(tc.d, tc.f, tc.platform); got != tc.want {
			t.Errorf("%s: Generated() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
