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

const exampleAudience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster"

func gcp(audience, email string) string {
	return `"targetAuth": "gcpWorkloadIdentity", "gcp": {"audience": "` + audience + `", "serviceAccountEmail": "` + email + `"},`
}

func TestDecodeGCP(t *testing.T) {
	const email = "tagwarden-sync@example-project.iam.gserviceaccount.com"
	in := strings.Replace(valid, maxTags, `"maxTags": 100, `+gcp(exampleAudience, email), 1)
	s, err := Decode(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if s.TargetAuth != AuthGCPWorkloadIdentity || *s.GCP != (GCP{Audience: exampleAudience, ServiceAccountEmail: email}) {
		t.Fatalf("decoded %+v", s)
	}
	if s.GCP.TokenAudience() != "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster" {
		t.Fatalf("token audience %s", s.GCP.TokenAudience())
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
		"gcp missing":        {maxTags, `"maxTags": 100, "sourceAuth": "gcpWorkloadIdentity",`},
		"gcp https audience": {maxTags, `"maxTags": 100, ` + gcp("https:"+exampleAudience, "")},
		"gcp other host":     {maxTags, `"maxTags": 100, ` + gcp(strings.Replace(exampleAudience, "googleapis.com", "example.internal", 1), "")},
		"gcp bad email":      {maxTags, `"maxTags": 100, ` + gcp(exampleAudience, "sync@example.internal")},
		"gcp endpoint":       {maxTags, `"maxTags": 100, ` + strings.Replace(gcp(exampleAudience, ""), "},", `, "stsEndpoint": "https://sts.example.internal/"},`, 1)},
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

func TestGARHosts(t *testing.T) {
	for host, want := range map[string]bool{
		"europe-west1-docker.pkg.dev":      true,
		"US-Docker.pkg.dev:443":            true,
		"gcr.io":                           true,
		"us.gcr.io":                        true,
		"eu.gcr.io":                        true,
		"asia.gcr.io":                      true,
		"europe-west1-docker.pkg.dev:5000": false,
		"europe-west1-docker.pkg.dev.example.internal": false,
		"docker.pkg.dev":           false,
		"europe-west1-npm.pkg.dev": false,
		"mirror.gcr.io":            false,
		"k8s.gcr.io":               false,
		"us-doc\u212Aer.pkg.dev":   false,
	} {
		if GARHost(host) != want {
			t.Errorf("GARHost(%q) = %v", host, !want)
		}
	}
}

func TestScannerURL(t *testing.T) {
	const (
		clusterLocal = "cluster.local"
		corpDomain   = "corp.example"
		fqdnURL      = "http://trivy.tagwarden-system.svc.cluster.local.:4954"
	)
	tests := []struct {
		raw, domain, want string
		inCluster         bool
		err               bool
	}{
		{raw: "http://trivy.tagwarden-system.svc:4954", domain: clusterLocal,
			want: fqdnURL, inCluster: true},
		{raw: "http://trivy.tagwarden-system.svc.cluster.local:4954/", domain: clusterLocal,
			want: "http://trivy.tagwarden-system.svc.cluster.local.:4954/", inCluster: true},
		{raw: fqdnURL, domain: clusterLocal,
			want: fqdnURL, inCluster: true},
		{raw: "http://trivy.ns.svc", domain: corpDomain,
			want: "http://trivy.ns.svc.corp.example.", inCluster: true},
		{raw: "http://trivy.ns.svc.cluster.local", domain: corpDomain,
			want: "http://trivy.ns.svc.corp.example.", inCluster: true},
		{raw: "https://trivy.ns.svc.corp.example:4954", domain: corpDomain,
			want: "https://trivy.ns.svc.corp.example.:4954", inCluster: true},
		{raw: "https://trivy.scanners.example.internal:4954", domain: clusterLocal,
			want: "https://trivy.scanners.example.internal.:4954"},
		{raw: "https://trivy.ns.svc.example.com", domain: clusterLocal,
			want: "https://trivy.ns.svc.example.com."},
		{raw: "https://Trivy.Example.Internal.", domain: clusterLocal,
			want: "https://trivy.example.internal."},
		{raw: "https://192.0.2.10:4954", domain: clusterLocal, want: "https://192.0.2.10:4954"},
		{raw: "https://[2001:db8::1]:4954", domain: clusterLocal, want: "https://[2001:db8::1]:4954"},
		{raw: "://bad", domain: clusterLocal, err: true},
		{raw: "https://", domain: clusterLocal, err: true},
	}
	for _, tt := range tests {
		got, inCluster, err := ScannerURL(tt.raw, tt.domain)
		if (err != nil) != tt.err || got != tt.want || inCluster != tt.inCluster {
			t.Errorf("ScannerURL(%q, %q) = %q, %v, %v; want %q, %v", tt.raw, tt.domain, got, inCluster, err, tt.want, tt.inCluster)
		}
	}
}
