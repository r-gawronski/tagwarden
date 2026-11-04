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

package main

import "testing"

const testURL = "http://x:4954"

func TestValidateTrivy(t *testing.T) {
	const (
		ver = "0.76.1"
		img = "registry.example.internal/p/trivy:" + ver +
			"@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	for _, tc := range []struct {
		name, image, version, url string
		ok                        bool
	}{
		{name: "unset", ok: true},
		{name: "all set", image: img, version: ver, url: "http://tagwarden-trivy.tagwarden-system.svc:4954", ok: true},
		{name: "only image", image: img},
		{name: "tag only image", image: "r/trivy:0.76.1", version: ver, url: testURL},
		{name: "bad version", image: img, version: "latest", url: testURL},
		{name: "no scheme", image: img, version: ver, url: "x:4954"},
		{name: "ftp", image: img, version: ver, url: "ftp://x"},
		{name: "fully qualified", image: img, version: ver,
			url: "http://tagwarden-trivy.tagwarden-system.svc.cluster.local.:4954", ok: true},
		{name: "userinfo", image: img, version: ver, url: "http://user@x:4954"},
		{name: "query", image: img, version: ver, url: "http://x:4954?a=b"},
		{name: "empty query", image: img, version: ver, url: "http://x:4954?"},
		{name: "fragment", image: img, version: ver, url: "http://x:4954#f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTrivy(tc.image, tc.version, tc.url); (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

func TestValidateTrivyTokenSecret(t *testing.T) {
	for _, tc := range []struct {
		name, ref, url string
		ok             bool
	}{
		{name: "unset", ok: true},
		{name: "unset with url", url: testURL, ok: true},
		{name: "set", ref: "tagwarden-trivy-token", url: testURL, ok: true},
		{name: "without url", ref: "tagwarden-trivy-token"},
		{name: "invalid name", ref: "Trivy_Token", url: testURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTrivyTokenSecret(tc.ref, tc.url); (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

func TestValidateClusterDomain(t *testing.T) {
	for d, ok := range map[string]bool{
		"cluster.local": true, "corp.example": true, "local": true,
		"": false, "cluster.local.": false, "Cluster.Local": false, "a b": false, "-x.local": false,
	} {
		if err := validateClusterDomain(d); (err == nil) != ok {
			t.Errorf("validateClusterDomain(%q) = %v, want ok %v", d, err, ok)
		}
	}
}
