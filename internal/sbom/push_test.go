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
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestPushRoundTrip pushes a referrer the way the sync Job will and reads
// it back, with the referrers API and with the sha256-<hex> tag fallback.
func TestPushRoundTrip(t *testing.T) {
	for _, referrers := range []bool{true, false} {
		t.Run(fmt.Sprintf("referrers API %v", referrers), func(t *testing.T) {
			srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(referrers), registry.Logger(log.New(io.Discard, "", 0))))
			defer srv.Close()
			repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/platform/app")
			if err != nil {
				t.Fatal(err)
			}
			img, err := random.Image(64, 1)
			if err != nil {
				t.Fatal(err)
			}
			subject, err := partial.Descriptor(img)
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(repo.Digest(subject.Digest.String()), img); err != nil {
				t.Fatal(err)
			}
			ref, err := Referrer{Format: CycloneDX, Document: []byte(cdxDoc), Subject: *subject, Generator: gen, Created: created}.Image()
			if err != nil {
				t.Fatal(err)
			}
			rd, _ := ref.Digest()
			if err := remote.Write(repo.Digest(rd.String()), ref); err != nil {
				t.Fatal(err)
			}

			idx, err := remote.Referrers(repo.Digest(subject.Digest.String()))
			if err != nil {
				t.Fatal(err)
			}
			im, err := idx.IndexManifest()
			if err != nil {
				t.Fatal(err)
			}
			var found []v1.Descriptor
			for _, m := range im.Manifests {
				if Generated(m, CycloneDX, "") {
					found = append(found, m)
				}
			}
			if len(found) != 1 || found[0].Digest != rd {
				t.Fatalf("referrers = %+v, want one generated SBOM %s", im.Manifests, rd)
			}
			if Generated(found[0], SPDX, "") {
				t.Error("Generated() matched the other format")
			}
		})
	}
}
