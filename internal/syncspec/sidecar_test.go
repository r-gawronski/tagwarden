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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

const devNull = "/dev/null"

// fakeTrivy records its arguments, one per line, and prints a report. A
// digest of b characters fails like a client error.
const fakeTrivy = `#!/bin/sh
if [ "$1" = version ]; then echo '{"Version":"0.76.1"}'; exit 0; fi
for a in "$@"; do printf '%s\n' "$a"; done > "$ARGS"
case "$*" in *bbbbbbbb*) echo FATAL >&2; exit 1 ;; esac
case "$*" in *"--format cyclonedx"*) echo '{"bomFormat":"CycloneDX"}'; exit 0 ;; esac
case "$*" in *"--format spdx-json"*) echo '{"spdxVersion":"SPDX-2.3"}'; exit 0 ;; esac
echo '[]'
`

// startSidecar runs the real sidecar loop against a fake trivy with env
// and returns the scan dir, the temp dir and the file the fake writes its
// arguments to.
func startSidecar(t *testing.T, env ...string) (scan, dir, args string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir = t.TempDir()
	scan, bin := filepath.Join(dir, "scandir"), filepath.Join(dir, "bin")
	for _, d := range []string{scan, bin} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte(fakeTrivy), 0o700); err != nil { //nolint:gosec // test binary
		t.Fatal(err)
	}
	script := strings.NewReplacer(
		"cd /scan", "cd "+scan,
		"/scan/cache", scan+"/cache",
		LayoutDir, filepath.Join(dir, "layout"),
		ScannerCAFile, filepath.Join(dir, "missing-ca.crt"),
	).Replace(SidecarScript)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sh", "-c", script) //nolint:gosec // the script under test
	args = filepath.Join(dir, "args")
	cmd.Env = append(os.Environ(), append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "ARGS=" + args}, env...)...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	return scan, dir, args
}

// TestSidecarScript runs the real sidecar loop against a fake trivy.
func TestSidecarScript(t *testing.T) {
	for _, javaDB := range []string{"Disabled", "PerJob"} {
		t.Run(javaDB, func(t *testing.T) {
			scan, dir, args := startSidecar(t, ScannerURLEnv+"=http://trivy.ns.svc:4954", ScannerTimeoutEnv+"=10m0s",
				ScannerJavaDBEnv+"="+javaDB, ScannerTemplateEnv+"="+vuln.ReportTemplate)
			waitFor(t, filepath.Join(scan, ScanVersionFile))
			// Names that are not 64 hex characters are dropped, never run.
			marker := filepath.Join(scan, "pwned")
			for _, n := range []string{"$(touch pwned)", "x;touch pwned", strings.Repeat("A", 64), "abc"} {
				if err := os.WriteFile(filepath.Join(scan, ScanReqDir, n+".ready"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			good, bad := strings.Repeat("a", 64), strings.Repeat("b", 64)
			for _, h := range []string{bad, good} {
				if err := os.WriteFile(filepath.Join(scan, ScanReqDir, h+".ready"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				waitFor(t, filepath.Join(scan, ScanOutDir, h+".exit"))
			}
			if exit, _ := os.ReadFile(filepath.Join(scan, ScanOutDir, bad+".exit")); string(exit) != "1\n" { //nolint:gosec // test temp dir
				t.Fatalf("failed scan exit %q", exit)
			}
			exit, _ := os.ReadFile(filepath.Join(scan, ScanOutDir, good+".exit"))   //nolint:gosec // test temp dir
			report, _ := os.ReadFile(filepath.Join(scan, ScanOutDir, good+".json")) //nolint:gosec // test temp dir
			got, _ := os.ReadFile(args)                                             //nolint:gosec // test temp dir
			if string(exit) != "0\n" || strings.TrimSpace(string(report)) != "[]" {
				t.Fatalf("exit %q, report %q", exit, report)
			}
			lines := strings.Split(string(got), "\n")
			want := []string{"image", "--server", "http://trivy.ns.svc:4954", "--token-header", "Trivy-Token",
				"--input", filepath.Join(dir, "layout") + "@sha256:" + good, "--scanners", "vuln",
				"--skip-db-update", "--skip-java-db-update", "--skip-version-check", "--disable-telemetry",
				"--timeout", "10m0s", "--config", "/dev/null", "--ignorefile", "/dev/null"}
			for i, w := range want {
				if i >= len(lines) || lines[i] != w {
					t.Fatalf("args %q, want prefix %q", lines, want)
				}
			}
			java := "--skip-files=**/*.jar,**/*.war,**/*.ear,**/*.par"
			if javaDB == "PerJob" {
				java = "--cache-dir=" + scan + "/cache"
			}
			if !strings.Contains(string(got), "\n"+java+"\n--format\ntemplate\n--template\n") ||
				!strings.Contains(string(got), vuln.ReportTemplate) || strings.Contains(string(got), "--cacert") {
				t.Fatalf("args %q", got)
			}
			left, _ := filepath.Glob(filepath.Join(scan, ScanReqDir, "*"))
			if _, err := os.Stat(marker); err == nil || len(left) != 0 {
				t.Fatalf("marker created or requests left: %v", left)
			}
		})
	}
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	for range 100 {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s not written", path)
}

// TestSidecarScriptSBOM runs the SBOM request kind of the real sidecar
// loop: the format comes from the suffix, the command has no server and no
// DB access, and a Job without the gate ignores scan requests.
func TestSidecarScriptSBOM(t *testing.T) {
	for _, javaDB := range []string{string(v1alpha1.JavaDBDisabled), string(v1alpha1.JavaDBPerJob)} {
		t.Run(javaDB, func(t *testing.T) {
			scan, dir, args := startSidecar(t, SBOMTimeoutEnv+"=5m0s", ScannerJavaDBEnv+"="+javaDB)
			waitFor(t, filepath.Join(scan, ScanVersionFile))
			req := func(n string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(scan, ScanReqDir, n), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a, b := strings.Repeat("a", 64), strings.Repeat("c", 64)
			// Without TAGWARDEN_SCANNER_URL a scan request is dropped; so are
			// unknown suffixes, bad names and a format smuggled into the name.
			for _, n := range []string{a + ".ready", a + ".json", a + ".cyclonedx.x", "$(touch pwned).cyclonedx",
				strings.Repeat("A", 64) + ".spdx-json", a + "x.cyclonedx", "abc.cyclonedx"} {
				req(n)
			}
			req(a + ".cyclonedx")
			waitFor(t, filepath.Join(scan, ScanOutDir, a+".cyclonedx.exit"))
			cdx, _ := os.ReadFile(args) //nolint:gosec // test temp dir
			req(b + ".spdx-json")
			waitFor(t, filepath.Join(scan, ScanOutDir, b+".spdx-json.exit"))
			spdx, _ := os.ReadFile(args) //nolint:gosec // test temp dir

			java := "--skip-files=**/*.jar,**/*.war,**/*.ear,**/*.par"
			if javaDB == string(v1alpha1.JavaDBPerJob) {
				java = "--cache-dir=" + scan + "/cache"
			}
			for _, c := range []struct {
				hex, format string
				got         []byte
			}{{a, "cyclonedx", cdx}, {b, "spdx-json", spdx}} {
				want := []string{"image", "--input", filepath.Join(dir, "layout") + "@sha256:" + c.hex, "--format", c.format,
					"--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-version-check",
					"--disable-telemetry", "--cache-backend", "memory", "--timeout", "5m0s",
					"--config", devNull, "--ignorefile", devNull, java, ""}
				if got := strings.Split(string(c.got), "\n"); !slices.Equal(got, want) {
					t.Fatalf("args %q, want %q", got, want)
				}
				exit, _ := os.ReadFile(filepath.Join(scan, ScanOutDir, c.hex+"."+c.format+".exit")) //nolint:gosec // test temp dir
				doc, _ := os.ReadFile(filepath.Join(scan, ScanOutDir, c.hex+"."+c.format+".json"))  //nolint:gosec // test temp dir
				if string(exit) != "0\n" || !strings.HasPrefix(string(doc), "{") {
					t.Fatalf("exit %q, doc %q", exit, doc)
				}
			}
			outs, _ := filepath.Glob(filepath.Join(scan, ScanOutDir, "*"))
			left, _ := filepath.Glob(filepath.Join(scan, ScanReqDir, "*"))
			if len(outs) != 4 || len(left) != 0 {
				t.Fatalf("outputs %v, requests left %v", outs, left)
			}
			if _, err := os.Stat(filepath.Join(scan, "pwned")); err == nil {
				t.Fatal("marker created")
			}
		})
	}
}

// TestSidecarScriptGatedIgnoresSBOMWithoutTimeout checks that a gated
// sidecar rendered without the SBOM timeout drops SBOM requests.
func TestSidecarScriptGatedIgnoresSBOMWithoutTimeout(t *testing.T) {
	scan, _, _ := startSidecar(t, ScannerURLEnv+"=http://trivy.ns.svc:4954", ScannerTimeoutEnv+"=10m0s",
		ScannerJavaDBEnv+"="+string(v1alpha1.JavaDBDisabled), ScannerTemplateEnv+"="+vuln.ReportTemplate)
	waitFor(t, filepath.Join(scan, ScanVersionFile))
	a := strings.Repeat("a", 64)
	for _, n := range []string{a + ".cyclonedx", a + ".ready"} {
		if err := os.WriteFile(filepath.Join(scan, ScanReqDir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, filepath.Join(scan, ScanOutDir, a+".exit"))
	if _, err := os.Stat(filepath.Join(scan, ScanOutDir, a+".cyclonedx.exit")); err == nil {
		t.Fatal("SBOM request answered without TAGWARDEN_SBOM_TIMEOUT")
	}
}
