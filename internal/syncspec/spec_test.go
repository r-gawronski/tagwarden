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
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

const (
	scannerVersion = "0.76.1"
	nextMinor      = "0.77.0"
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
		"max over limit":     {maxTags, `"maxTags": 100001,`},
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
		"new version":  `{"v":3}`,
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

func TestParseReportV2(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	entry := func(extra string) string {
		return `{"v":2,"findings":1,"blocked":1,"gate":"ok","javaScanned":false,"tagFindings":[{"tag":"v1","digest":"` + digest +
			`","verdict":"Findings","outcome":"Blocked","severity":"Critical","counts":{"critical":1},"topIDs":["CVE-2026-1"],"scannedAt":"2026-11-03T10:00:00Z"` + extra + `}],"synced":[]}`
	}
	r, err := ParseReport(strings.Replace(entry(`,"dbUpdatedAt":"2026-11-03T09:00:00Z"`), `"synced":[]`, `"synced":[],"judged":[{"tag":"v1","digest":"`+digest+`"}]`, 1))
	if err != nil || r.Findings != 1 || r.Blocked != 1 || r.JavaScanned == nil || *r.JavaScanned || len(r.TagFindings) != 1 ||
		r.TagFindings[0].Outcome != v1alpha1.OutcomeBlocked || r.TagFindings[0].Counts.Critical != 1 || len(r.Judged) != 1 {
		t.Fatalf("report %+v, err %v", r, err)
	}
	if _, err := ParseReport(`{"v":2,"synced":[]}`); err != nil {
		t.Fatalf("minimal v2: %v", err)
	}
	bad := map[string]string{
		"gate fields in v1": `{"v":1,"findings":1}`,
		"judged in v1":      `{"v":1,"judged":[{"tag":"v1","digest":"` + digest + `"}]}`,
		"bad judged":        `{"v":2,"judged":[{"tag":"v1","digest":"sha256:1"}]}`,
		"bad fingerprint":   `{"v":2,"judgedFingerprint":"abc"}`,
		"fingerprint in v1": `{"v":1,"judgedFingerprint":"` + strings.Repeat("a", 64) + `"}`,
		"negative count":    `{"v":2,"scanErrors":-1}`,
		"unknown gate":      `{"v":2,"gate":"fine"}`,
		"bad id":            strings.Replace(entry(""), "CVE-2026-1", "cve; rm", 1),
		"too many ids":      strings.Replace(entry(""), `"CVE-2026-1"`, `"CVE-1","CVE-2","CVE-3","CVE-4"`, 1),
		"bad severity":      strings.Replace(entry(""), `"Critical"`, `"Severe"`, 1),
		"bad outcome":       strings.Replace(entry(""), `"Blocked"`, `"Deleted"`, 1),
		"negative severity": strings.Replace(entry(""), `"critical":1`, `"critical":-1`, 1),
		"error w/o reason":  strings.Replace(entry(""), `"Findings"`, `"ScanError"`, 1),
		"unknown reason":    entry(`,"scanError":"Oops"`),
		"bad db time":       entry(`,"dbUpdatedAt":"yesterday"`),
		"bad tag":           strings.Replace(entry(""), `"tag":"v1"`, `"tag":"../x"`, 1),
		"no scannedAt":      strings.Replace(entry(""), `,"scannedAt":"2026-11-03T10:00:00Z"`, "", 1),
		"zero scannedAt":    strings.Replace(entry(""), "2026-11-03T10:00:00Z", "0001-01-01T00:00:00Z", 1),
		"future scannedAt":  strings.Replace(entry(""), "2026-11-03T10:00:00Z", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), 1),
	}
	for name, msg := range bad {
		if _, err := ParseReport(msg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestNewGate(t *testing.T) {
	expires := metav1.NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	excs := []v1alpha1.VulnerabilityException{{
		ObjectMeta: metav1.ObjectMeta{Name: "accept"},
		Spec: v1alpha1.VulnerabilityExceptionSpec{Namespaces: []string{"team-a"}, Repository: "docker.io/library/nginx",
			Vulnerabilities: []string{"CVE-2026-1"}, Expires: expires},
	}}
	d := ScannerDefaults{URL: "http://tagwarden-trivy.tagwarden-system.svc:4954", Version: scannerVersion, Image: "trivy@sha256:" + strings.Repeat("a", 64)}
	g, err := NewGate(&v1alpha1.VulnerabilityGate{Enabled: true}, d, "cluster.local", excs, []JudgedTag{{Tag: "v1", Digest: "sha256:" + strings.Repeat("b", 64)}}, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	p := g.Policy()
	if p.Action != vuln.Report || p.Severity != vuln.Critical || p.OnScanError != vuln.Report ||
		g.MaxDBAge.Duration != DefaultMaxDBAge || g.Scanner.Timeout.Duration != DefaultScannerTimeout ||
		g.Scanner.JavaDB != v1alpha1.JavaDBDisabled || g.Scanner.Version != d.Version || len(g.Judged) != 1 ||
		g.Scanner.URL != "http://tagwarden-trivy.tagwarden-system.svc.cluster.local.:4954" || !g.Scanner.InCluster ||
		g.RescanInterval.Duration != 0 || g.OnVulnerableTag != "" {
		t.Fatalf("defaults %+v %+v", g, p)
	}
	ve := g.VulnExceptions()
	if len(ve) != 1 || ve[0].Name != "accept" || !ve[0].Expires.Equal(expires.Time) || ve[0].Vulnerabilities[0] != "CVE-2026-1" {
		t.Fatalf("exceptions %+v", ve)
	}

	g, err = NewGate(&v1alpha1.VulnerabilityGate{
		Action: v1alpha1.GateActionBlock, Severity: v1alpha1.SeverityThresholdHigh, OnScanError: v1alpha1.GateActionBlock,
		IgnoreUnfixed: true, IncludeUnknown: true, MaxDBAge: &metav1.Duration{Duration: time.Hour},
		RescanInterval: &metav1.Duration{Duration: 24 * time.Hour}, OnVulnerableTag: v1alpha1.OnVulnerableTagUntag,
		Scanner: &v1alpha1.ScannerSpec{URL: "https://trivy.example.internal", Image: "x@sha256:" + strings.Repeat("c", 64), Version: nextMinor,
			Timeout: &metav1.Duration{Duration: time.Minute}, JavaDB: v1alpha1.JavaDBPerJob, JavaDBRepository: "registry.example.internal/platform/trivy-java-db:1"},
	}, d, "cluster.local", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	p = g.Policy()
	if p.Action != vuln.Block || p.Severity != vuln.High || p.OnScanError != vuln.Block || !p.IgnoreUnfixed || !p.IncludeUnknown ||
		g.Scanner.URL != "https://trivy.example.internal." || g.Scanner.InCluster || g.Scanner.Version != nextMinor || g.Scanner.JavaDB != v1alpha1.JavaDBPerJob ||
		g.RescanInterval.Duration != 24*time.Hour || g.OnVulnerableTag != v1alpha1.OnVulnerableTagUntag {
		t.Fatalf("overrides %+v %+v", g, p)
	}
}

func TestGateFingerprint(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	exc := func(name string, expires time.Time) GateException {
		return GateException{Name: name, Namespaces: []string{"b", "a"}, Repository: "docker.io/library/nginx",
			Vulnerabilities: []string{"CVE-2", "CVE-1"}, Expires: metav1.NewTime(expires)}
	}
	base := func() *Gate {
		return &Gate{Action: v1alpha1.GateActionReport, Severity: v1alpha1.SeverityThresholdCritical, OnScanError: v1alpha1.GateActionReport,
			Scanner:    GateScanner{Version: scannerVersion},
			Exceptions: []GateException{exc("x", now.Add(time.Hour)), exc("y", now.Add(2*time.Hour))}}
	}
	fp := base().Fingerprint(now)
	if len(fp) != 64 {
		t.Fatal(fp)
	}
	same := map[string]func(g *Gate){
		"exception order": func(g *Gate) { g.Exceptions[0], g.Exceptions[1] = g.Exceptions[1], g.Exceptions[0] },
		"namespace order": func(g *Gate) { g.Exceptions[0].Namespaces = []string{"a", "b"} },
		"patch version":   func(g *Gate) { g.Scanner.Version = "0.76.9" },
		"max DB age":      func(g *Gate) { g.MaxDBAge.Duration = time.Hour },
		"judged":          func(g *Gate) { g.Judged = []JudgedTag{{Tag: "v1"}} },
		"rescan interval": func(g *Gate) { g.RescanInterval.Duration = time.Hour },
		"untag":           func(g *Gate) { g.OnVulnerableTag, g.Untaggable = v1alpha1.OnVulnerableTagUntag, []string{"v1"} },
		"expired dropped": func(g *Gate) { g.Exceptions = append(g.Exceptions, exc("z", now)) },
		"timezone of time": func(g *Gate) {
			g.Exceptions[0].Expires = metav1.NewTime(now.Add(time.Hour).In(time.FixedZone("x", 3600)))
		},
	}
	for name, mod := range same {
		g := base()
		mod(g)
		if g.Fingerprint(now) != fp {
			t.Errorf("%s changed the fingerprint", name)
		}
	}
	differ := map[string]func(g *Gate){
		"stricter action":     func(g *Gate) { g.Action = v1alpha1.GateActionBlock },
		"lower severity":      func(g *Gate) { g.Severity = v1alpha1.SeverityThresholdHigh },
		"ignore unfixed":      func(g *Gate) { g.IgnoreUnfixed = true },
		"include unknown":     func(g *Gate) { g.IncludeUnknown = true },
		"block on scan error": func(g *Gate) { g.OnScanError = v1alpha1.GateActionBlock },
		"minor version":       func(g *Gate) { g.Scanner.Version = nextMinor },
		"exception gone":      func(g *Gate) { g.Exceptions = g.Exceptions[:1] },
		"exception IDs":       func(g *Gate) { g.Exceptions[0].Vulnerabilities = []string{"CVE-1"} },
		"expiry moved":        func(g *Gate) { g.Exceptions[0].Expires = metav1.NewTime(now.Add(3 * time.Hour)) },
		"java DB per job":     func(g *Gate) { g.Scanner.JavaDB = v1alpha1.JavaDBPerJob },
	}
	for name, mod := range differ {
		g := base()
		mod(g)
		if g.Fingerprint(now) == fp {
			t.Errorf("%s kept the fingerprint", name)
		}
	}
	// An exception that expires between runs changes the fingerprint.
	if base().Fingerprint(now.Add(90*time.Minute)) == fp {
		t.Error("expiry kept the fingerprint")
	}
}

func TestDecodeGate(t *testing.T) {
	base := func(gate string) string {
		return `{"mirror":{"namespace":"team-a","name":"auto-0123456789abcdef"},"source":"docker.io/library/nginx",
			"target":"registry.example.internal/shared/docker.io/library/nginx","tags":{"tags":["1.27"]},
			"onTagMutation":"Fail","allowedSources":["docker.io"],"gate":` + gate + `}`
	}
	gate := func(mod func(map[string]any)) string {
		g := map[string]any{
			"action": "Block", "severity": "Critical", "onScanError": "Report", "maxDBAge": "72h",
			"scanner": map[string]any{"url": "http://tagwarden-trivy.tagwarden-system.svc:4954", "version": scannerVersion, "timeout": "10m", "javaDB": "Disabled"},
		}
		mod(g)
		b, _ := json.Marshal(g)
		return string(b)
	}
	scanner := func(k string, v any) func(map[string]any) {
		return func(g map[string]any) { g["scanner"].(map[string]any)[k] = v }
	}
	s, err := Decode(strings.NewReader(base(gate(func(map[string]any) {}))))
	if err != nil || s.Gate == nil || s.Gate.Policy().Action != vuln.Block {
		t.Fatalf("spec %+v, err %v", s.Gate, err)
	}
	// NewGate writes fully qualified hosts with a trailing dot.
	if _, err := Decode(strings.NewReader(base(gate(scanner("url", "http://tagwarden-trivy.tagwarden-system.svc.cluster.local.:4954"))))); err != nil {
		t.Fatalf("trailing dot: %v", err)
	}
	if _, err := Decode(strings.NewReader(base(gate(func(g map[string]any) {
		scanner("javaDB", "PerJob")(g)
		scanner("javaDBRepository", "registry.example.internal/platform/trivy-java-db:1")(g)
	})))); err != nil {
		t.Fatalf("PerJob: %v", err)
	}
	for name, mod := range map[string]func(map[string]any){
		"action":            func(g map[string]any) { g["action"] = "Quarantine" },
		"onScanError":       func(g map[string]any) { g["onScanError"] = "" },
		"severity":          func(g map[string]any) { g["severity"] = "Unknown" },
		"maxDBAge":          func(g map[string]any) { g["maxDBAge"] = "0s" },
		"url scheme":        scanner("url", "ftp://trivy"),
		"url credentials":   scanner("url", "https://user:pass@trivy.example.internal"),
		"url path":          scanner("url", "https://trivy.example.internal/x"),
		"version":           scanner("version", "latest"),
		"timeout":           scanner("timeout", "2h"),
		"javaDB":            scanner("javaDB", "Shared"),
		"PerJob without DB": scanner("javaDB", "PerJob"),
		"DB in other host": func(g map[string]any) {
			scanner("javaDB", "PerJob")(g)
			scanner("javaDBRepository", "ghcr.io/aquasecurity/trivy-java-db:1")(g)
		},
		"exception digest": func(g map[string]any) {
			g["exceptions"] = []any{map[string]any{"name": "x", "namespaces": []string{"a"}, "repository": "r", "digests": []string{"sha256:1"}, "expires": "2027-01-01T00:00:00Z"}}
		},
		"exception no names": func(g map[string]any) {
			g["exceptions"] = []any{map[string]any{"name": "x", "repository": "r", "expires": "2027-01-01T00:00:00Z"}}
		},
		"fingerprint":     func(g map[string]any) { g["judgedFingerprint"] = "nope" },
		"judged":          func(g map[string]any) { g["judged"] = []any{map[string]any{"tag": "v1", "digest": "sha256:1"}} },
		"unknown field":   func(g map[string]any) { g["token"] = "s3cret" },
		"onVulnerableTag": func(g map[string]any) { g["onVulnerableTag"] = "Delete" },
		"untag on report": func(g map[string]any) { g["action"], g["onVulnerableTag"] = "Report", "Untag" },
		"untaggable tag":  func(g map[string]any) { g["untaggable"] = []string{"../x"} },
		"rescanInterval":  func(g map[string]any) { g["rescanInterval"] = "-1h" },
	} {
		if _, err := Decode(strings.NewReader(base(gate(mod)))); err == nil {
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

func TestGateHolds(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	g := &Gate{}
	if !g.Holds(JudgedTag{}, now) {
		t.Error("without a rescan interval every judged pair holds")
	}
	g.RescanInterval.Duration = time.Hour
	for name, tc := range map[string]struct {
		at   time.Time
		want bool
	}{
		"recent":      {now.Add(-time.Minute), true},
		"at the edge": {now.Add(-time.Hour), true},
		"older":       {now.Add(-time.Hour - time.Second), false},
		"no judgedAt": {time.Time{}, false},
	} {
		if got := g.Holds(JudgedTag{JudgedAt: tc.at}, now); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestParseRescanReport(t *testing.T) {
	finding := func(verdict, action string) string {
		f := `{"tag":"v1","digest":"sha256:` + strings.Repeat("a", 64) + `","verdict":"` + verdict + `","outcome":"Copied","scannedAt":"2026-11-03T10:00:00Z"`
		if verdict == "ScanError" {
			f += `,"scanError":"ScanFailed"`
		}
		if action != "" {
			f += `,"rescanAction":"` + action + `"`
		}
		return f + `}`
	}
	msg := func(rescan bool, f string) string {
		return fmt.Sprintf(`{"v":2,"synced":[],"rescan":%v,"tagFindings":[%s]}`, rescan, f)
	}
	for _, ok := range []string{msg(true, finding("Findings", "Kept")), msg(true, finding("Findings", "UntagRefused")),
		msg(true, finding("ScanError", "")), msg(false, finding("Findings", ""))} {
		if _, err := ParseReport(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{msg(true, finding("Findings", "")), msg(true, finding("Findings", "Deleted")),
		msg(true, finding("ScanError", "Kept")), msg(false, finding("Findings", "Kept")), `{"v":1,"synced":[],"rescan":true}`} {
		if _, err := ParseReport(bad); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}

func TestParseReportSelection(t *testing.T) {
	ok := `{"v":1,"synced":[],"selection":{"listed":3,"prerelease":1,"selected":0,"missing":2,"missingTags":["a","b"]}}`
	r, err := ParseReport(ok)
	if err != nil {
		t.Fatal(err)
	}
	if s := r.Selection; s == nil || s.Listed != 3 || s.Prerelease != 1 || s.Selected != 0 || s.Missing != 2 || len(s.MissingTags) != 2 {
		t.Errorf("selection %+v", s)
	}
	b, _ := json.Marshal(r)
	if r2, err := ParseReport(string(b)); err != nil || r2.Selection.Missing != 2 {
		t.Errorf("round trip: %v %s", err, b)
	}
	if r, err := ParseReport(`{"v":1,"synced":[]}`); err != nil || r.Selection != nil {
		t.Errorf("old report: %v %+v", err, r.Selection)
	}
	for name, msg := range map[string]string{
		"negative":     `{"v":1,"selection":{"listed":-1}}`,
		"invalid name": `{"v":1,"selection":{"missingTags":["a b"]}}`,
		"too many":     `{"v":1,"selection":{"missingTags":["a","b","c","d","e","f"]}}`,
	} {
		if _, err := ParseReport(msg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
