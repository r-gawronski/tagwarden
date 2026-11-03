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

package vuln

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"text/template"
)

const sampleReport = `[{"id":"CVE-2026-0001","pkg":"libssl3","ver":"3.1.4-r5","fix":"3.1.4-r6","sev":"CRITICAL","status":"fixed"},
{"id":"DLA-3000-1","pkg":"zlib","ver":"1.2","fix":"","sev":"UNKNOWN","status":"affected"},
{"id":"GHSA-xxxx-yyyy-zzzz","pkg":"left\\\"pad","ver":"1.0.0","fix":"","sev":"HIGH","status":"will_not_fix"}]`

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{"sample", sampleReport, 3, nil},
		{"empty list", "[]", 0, nil},
		{"empty input", "", 0, ErrMalformed},
		{"not json", "FATAL boom", 0, ErrMalformed},
		{"null", "null", 0, ErrMalformed},
		{"object", "{}", 0, ErrMalformed},
		{"trailing data", "[] []", 0, ErrMalformed},
		{"truncated", sampleReport[:40], 0, ErrMalformed},
		{"missing id", `[{"id":"","sev":"HIGH"}]`, 0, ErrMalformed},
		{"unknown severity", `[{"id":cve1,"sev":"SEVERE"}]`, 0, ErrMalformed},
		{"lowercase severity", `[{"id":cve1,"sev":"high"}]`, 0, ErrMalformed},
		{"id too long", `[{"id":"` + strings.Repeat("A", 200) + `","sev":"LOW"}]`, 0, ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tc.in))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if len(got) != tc.want {
				t.Fatalf("len = %d, want %d", len(got), tc.want)
			}
		})
	}
}

func TestParseFields(t *testing.T) {
	got, err := Parse(strings.NewReader(sampleReport))
	if err != nil {
		t.Fatal(err)
	}
	want := Finding{ID: "CVE-2026-0001", Pkg: "libssl3", Version: "3.1.4-r5", Fix: "3.1.4-r6", Severity: Critical, Status: statusFixed}
	if got[0] != want {
		t.Fatalf("got %+v, want %+v", got[0], want)
	}
	if got[2].Pkg != `left\"pad` {
		t.Fatalf("escape lost: %q", got[2].Pkg)
	}
}

func TestParseSizeCap(t *testing.T) {
	// A valid array padded with spaces just over the cap.
	big := bytes.Repeat([]byte(" "), MaxReportBytes)
	over := append([]byte("[]"), big...)
	if _, err := Parse(bytes.NewReader(over)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// Exactly at the cap is accepted.
	at := append([]byte("[]"), big[:MaxReportBytes-2]...)
	if _, err := Parse(bytes.NewReader(at)); err != nil {
		t.Fatalf("at cap: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sampleReport)
	f.Add("[]")
	f.Add("")
	f.Add(`[{"id":cve1,"sev":"LOW"}`)
	f.Fuzz(func(t *testing.T, in string) {
		got, err := Parse(strings.NewReader(in))
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		for _, x := range got {
			if x.ID == "" || x.Severity.rank() < 0 {
				t.Fatalf("invalid finding accepted: %+v", x)
			}
		}
	})
}

func TestReportTemplateRendersParsableOutput(t *testing.T) {
	// Stand-in for Trivy's JSON-escaping escapeString and result structs.
	type vulnerability struct {
		VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Status string
	}
	type result struct{ Vulnerabilities []vulnerability }
	tpl, err := template.New("r").Funcs(template.FuncMap{
		"escapeString": func(s string) string { b, _ := json.Marshal(s); return string(b[1 : len(b)-1]) },
	}).Parse(ReportTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for _, results := range [][]result{
		nil,
		{{}, {Vulnerabilities: []vulnerability{{cve1, "a\"b", "1", "", "HIGH", "affected"}}}, {Vulnerabilities: []vulnerability{{"CVE-2", "c", "1", "2", "LOW", "fixed"}}}},
	} {
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, results); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(&buf); err != nil {
			t.Fatalf("%v: %q", err, buf.String())
		}
	}
}
