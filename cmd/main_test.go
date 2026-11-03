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
		{name: "tag only image", image: "r/trivy:0.76.1", version: ver, url: "http://x:4954"},
		{name: "bad version", image: img, version: "latest", url: "http://x:4954"},
		{name: "no scheme", image: img, version: ver, url: "x:4954"},
		{name: "ftp", image: img, version: ver, url: "ftp://x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTrivy(tc.image, tc.version, tc.url); (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}
