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
  "maxArtifactSize": 1048576,
  "allowedSources": ["registry.k8s.io"],
  "deniedCIDRs": ["10.96.0.0/12", "fd00:10::/108"]
}`

func TestDecode(t *testing.T) {
	s, err := Decode(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if s.Mirror.Namespace != "team-a" || s.Mirror.Name != "pause" || s.Tags.KeepLatest != 2 ||
		s.Tags.Include[0] != `^3\.` || s.MaxTags != 100 || s.MaxArtifactSize != 1<<20 || s.RequiredPlatforms[0] != "linux/amd64" {
		t.Fatalf("decoded %+v", s)
	}
	if s.SourceRepo.String() != "registry.k8s.io/pause" || s.TargetRepo.RegistryStr() != "registry.example.internal" {
		t.Fatalf("repositories %v %v", s.SourceRepo, s.TargetRepo)
	}
	if s.AllowedSources[0] != "registry.k8s.io" || len(s.DeniedPrefixes) != 2 || s.DeniedPrefixes[0].String() != "10.96.0.0/12" { //nolint:goconst // readable fixtures
		t.Fatalf("source checks %v %v", s.AllowedSources, s.DeniedPrefixes)
	}
}

const maxTags = `"maxTags": 100,`

const zeroGUID = `"00000000-0000-0000-0000-000000000000"`

func azure(clientID, host string) string {
	return `"targetAuth": "azureWorkloadIdentity", "azure": {"clientID": ` + clientID + `, "tenantID": ` + zeroGUID +
		`, "authorityHost": ` + host + `},`
}

func TestDecodeAzure(t *testing.T) {
	in := strings.Replace(valid, maxTags, `"maxTags": 100, `+azure(zeroGUID, `"https://login.microsoftonline.com/"`)+` "sourceAuth": "azureWorkloadIdentity",`, 1)
	s, err := Decode(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if s.TargetAuth != AuthAzureWorkloadIdentity || s.SourceAuth != AuthAzureWorkloadIdentity || s.Azure.AuthorityHost != DefaultAzureAuthorityHost {
		t.Fatalf("decoded %+v", s)
	}
}

func aws(role, region string) string {
	return `"sourceAuth": "awsWorkloadIdentity", "aws": {"roleARN": "` + role + `", "region": "` + region + `"},`
}

const exampleRole = "arn:aws:iam::123456789012:role/tagwarden-sync"

func TestDecodeAWS(t *testing.T) {
	in := strings.Replace(valid, maxTags, `"maxTags": 100, `+aws(exampleRole, "eu-west-1"), 1)
	s, err := Decode(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if s.SourceAuth != AuthAWSWorkloadIdentity || *s.AWS != (AWS{RoleARN: exampleRole, Region: "eu-west-1"}) {
		t.Fatalf("decoded %+v", s)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]struct{ old, new string }{
		"unknown field":      {maxTags, `"maxTags": 100, "extra": 1,`},
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
		"negative max":       {maxTags, `"maxTags": -1,`},
		"negative size":      {`"maxArtifactSize": 1048576`, `"maxArtifactSize": -1`},
		"trailing data":      {"\n}", "\n}{}"},
		"no allowed sources": {`["registry.k8s.io"]`, `[]`},
		"empty allowed host": {`["registry.k8s.io"]`, `[""]`},
		"bad CIDR":           {`"10.96.0.0/12"`, `"10.96.0.0/33"`},
		"unknown auth":       {maxTags, `"maxTags": 100, "targetAuth": "awsWebIdentity",`},
		"azure missing":      {maxTags, `"maxTags": 100, "sourceAuth": "azureWorkloadIdentity",`},
		"azure bad client":   {maxTags, `"maxTags": 100, ` + azure(`"x"`, `"https://login.example.internal/"`)},
		"azure http host":    {maxTags, `"maxTags": 100, ` + azure(zeroGUID, `"http://login.example.internal/"`)},
		"azure no host":      {maxTags, `"maxTags": 100, ` + azure(zeroGUID, `""`)},
		"aws missing":        {maxTags, `"maxTags": 100, "targetAuth": "awsWorkloadIdentity",`},
		"aws bad role":       {maxTags, `"maxTags": 100, ` + aws("arn:aws:iam::123456789012:user/sync", "eu-west-1")},
		"aws bad region":     {maxTags, `"maxTags": 100, ` + aws(exampleRole, "eu-west-1.example.internal")},
		"aws iso region":     {maxTags, `"maxTags": 100, ` + aws(exampleRole, "us-isob-east-1")},
		"aws partition":      {maxTags, `"maxTags": 100, ` + aws(exampleRole, "cn-north-1")},
		"aws gov partition":  {maxTags, `"maxTags": 100, ` + aws("arn:aws-us-gov:iam::123456789012:role/sync", "us-east-1")},
		"aws endpoint":       {maxTags, `"maxTags": 100, ` + strings.Replace(aws(exampleRole, "eu-west-1"), "},", `, "stsEndpoint": "https://sts.example.internal/"},`, 1)},
		"azure scope":        {maxTags, `"maxTags": 100, ` + strings.Replace(azure(zeroGUID, `"https://login.microsoftonline.com/"`), "},", `, "scope": "https://management.azure.com/.default"},`, 1)},
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

func TestAllowedSource(t *testing.T) {
	cases := []struct {
		host    string
		allowed []string
		want    bool
	}{
		{"registry.k8s.io", []string{"quay.io", "registry.k8s.io"}, true}, //nolint:goconst // readable fixtures
		{"Registry.K8s.io", []string{"registry.k8s.io"}, true},
		{"registry.k8s.io", []string{"registry.k8s.io:443"}, false},
		{"registry.k8s.io:5000", []string{"registry.k8s.io"}, false},
		{"index.docker.io", []string{"docker.io"}, true}, //nolint:goconst // readable fixtures
		{"index.docker.io", []string{"registry-1.docker.io"}, true},
		{"docker.io", []string{"index.docker.io"}, true},
		{"evil.docker.io", []string{"docker.io"}, false},
	}
	for _, tc := range cases {
		if got := AllowedSource(tc.host, tc.allowed); got != tc.want {
			t.Errorf("AllowedSource(%q, %v) = %v", tc.host, tc.allowed, got)
		}
	}
}

func TestParseReport(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	r, err := ParseReport(`{"v":1,"copied":1,"synced":[{"tag":"v1.0.0","digest":"` + digest + `"}],"future":true}`)
	if err != nil || r.Copied != 1 || len(r.Synced) != 1 || r.Synced[0].Digest != digest {
		t.Fatalf("report %+v, err %v", r, err)
	}
	bad := map[string]string{
		"empty":        ``,
		"garbage":      `not json`,
		"too large":    `{"v":1,"errors":["` + strings.Repeat("x", MaxReportSize) + `"]}`,
		"no version":   `{"copied":1}`,
		"new version":  `{"v":2}`,
		"negative":     `{"v":1,"failed":-1}`,
		"bad tag":      `{"v":1,"synced":[{"tag":"../x","digest":"` + digest + `"}]}`,
		"bad digest":   `{"v":1,"synced":[{"tag":"v1","digest":"sha256:abc"}]}`,
		"wrong type":   `{"v":1,"synced":"v1"}`,
		"trailing obj": `{"v":1}{"v":1}`,
	}
	for name, msg := range bad {
		if _, err := ParseReport(msg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestAzureHosts(t *testing.T) {
	for host, want := range map[string]bool{
		"myregistry.azurecr.io": true, "MyRegistry.azurecr.us": true, "reg-abc123.azurecr.cn:443": true,
		"myregistry.azurecr.io:5000": false, "azurecr.io": false, "myregistry.azurecr.io.example.internal": false,
		"evil.example.internal": false, "myregistry.azurecr.com": false,
		"myregistry\u212A.azurecr.io": false, "myregistry.azurecr.\u0130o": false,
	} {
		if ACRHost(host) != want {
			t.Errorf("ACRHost(%q) = %v", host, !want)
		}
	}
	for u, want := range map[string]bool{
		"https://login.microsoftonline.com/": true, "https://login.microsoftonline.us": true,
		"https://login.partner.microsoftonline.cn/": true, "https://login.chinacloudapi.cn/": true,
		"http://login.microsoftonline.com/": false, "https://login.microsoftonline.com.example.internal/": false,
		"https://login.example.internal/": false, "https://login.microsoftonline.com/tenant/": false,
	} {
		if AzureAuthority(u) != want {
			t.Errorf("AzureAuthority(%q) = %v", u, !want)
		}
	}
}

func TestECRHosts(t *testing.T) {
	type res struct {
		region string
		fips   bool
	}
	for host, want := range map[string]*res{
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com":                  {"eu-west-1", false},
		"123456789012.DKR.ECR.US-EAST-1.amazonaws.com:443":              {"us-east-1", false},
		"123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com":         {"us-gov-west-1", true},
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn":              {"cn-north-1", false},
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com:5000":             nil,
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com.cn":               nil,
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com":                 nil,
		"123456789012.dkr.ecr-fips.cn-north-1.amazonaws.com.cn":         nil,
		"12345678901.dkr.ecr.eu-west-1.amazonaws.com":                   nil,
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com.example.internal": nil,
		"123456789012.dkr-ecr.eu-west-1.on.aws":                         nil,
		"123456789012.dkr.ecr.us-isob-east-1.amazonaws.com":             nil,
		"public.ecr.aws": nil,
		"123456789012.dkr.ecr.eu-west-1.amazonaws.\u212Aom": nil,
	} {
		region, fips, ok := ECRHost(host)
		if ok != (want != nil) || want != nil && (region != want.region || fips != want.fips) {
			t.Errorf("ECRHost(%q) = %q %v %v", host, region, fips, ok)
		}
	}
}
