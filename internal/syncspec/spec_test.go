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
	"strings"
	"testing"
)

const valid = `{
  "mirror": {"namespace": "team-a", "name": "pause"},
  "source": "registry.k8s.io/pause",
  "target": "registry.example.internal/team-a/pause",
  "tags": {"include": ["^3\\."], "keepLatest": 2},
  "requiredPlatforms": ["linux/amd64"],
  "onTagMutation": "Fail",
  "maxTags": 100,
  "allowedSources": ["registry.k8s.io"],
  "deniedCIDRs": ["10.96.0.0/12", "fd00:10::/108"]
}`

func TestDecode(t *testing.T) {
	s, err := Decode(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if s.Mirror.Namespace != "team-a" || s.Mirror.Name != "pause" || s.Tags.KeepLatest != 2 ||
		s.Tags.Include[0] != `^3\.` || s.MaxTags != 100 || s.RequiredPlatforms[0] != "linux/amd64" {
		t.Fatalf("decoded %+v", s)
	}
	if s.SourceRepo.String() != "registry.k8s.io/pause" || s.TargetRepo.RegistryStr() != "registry.example.internal" {
		t.Fatalf("repositories %v %v", s.SourceRepo, s.TargetRepo)
	}
	if s.AllowedSources[0] != "registry.k8s.io" || len(s.DeniedPrefixes) != 2 || s.DeniedPrefixes[0].String() != "10.96.0.0/12" {
		t.Fatalf("source checks %v %v", s.AllowedSources, s.DeniedPrefixes)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]struct{ old, new string }{
		"unknown field":      {`"maxTags": 100,`, `"maxTags": 100, "extra": 1,`},
		"unknown tag field":  {`"keepLatest": 2`, `"keepLatest": 2, "latest": true`},
		"no namespace":       {`"namespace": "team-a"`, `"namespace": ""`},
		"no name":            {`"name": "pause"`, `"name": ""`},
		"implicit registry":  {`"registry.k8s.io/pause"`, `"pause"`},
		"bad target":         {`"registry.example.internal/team-a/pause"`, `"registry.example.internal/Team"`},
		"tagged source":      {`"registry.k8s.io/pause"`, `"registry.k8s.io/pause:3.10"`},
		"bad policy":         {`"^3\\."`, `"("`},
		"bad platform":       {`"linux/amd64"`, `"linux/amd64/v1/x/y"`},
		"no mutation policy": {`"onTagMutation": "Fail"`, `"onTagMutation": ""`},
		"bad mutation":       {`"Fail"`, `"Replace"`},
		"negative max":       {`"maxTags": 100,`, `"maxTags": -1,`},
		"trailing data":      {"\n}", "\n}{}"},
		"no allowed sources": {`["registry.k8s.io"]`, `[]`},
		"empty allowed host": {`["registry.k8s.io"]`, `[""]`},
		"bad CIDR":           {`"10.96.0.0/12"`, `"10.96.0.0/33"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := strings.Replace(valid, tc.old, tc.new, 1)
			if in == valid {
				t.Fatal("fixture not changed")
			}
			if _, err := Decode(strings.NewReader(in)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}
