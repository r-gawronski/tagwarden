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
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/vuln"
)

// Fixed paths of a gated sync pod. The sync container and the scanner
// sidecar share them; nothing in them comes from tenant input.
const (
	// LayoutDir holds the OCI layout of the artifact being scanned. The
	// sidecar mounts its volume read-only.
	LayoutDir = "/work/layout"
	// ScanDir is the volume for requests, reports, the sidecar's TMPDIR
	// and, with javaDB PerJob, the Trivy cache.
	ScanDir = "/scan"
	// ScannerCAFile is the optional CA bundle of an https Trivy server.
	ScannerCAFile = "/var/run/tagwarden/scanner-ca/ca.crt"
)

// Sidecar protocol, relative to ScanDir. For a manifest digest
// sha256:<hex> the sync container removes out/<hex>.json and out/<hex>.exit,
// then creates req/<hex>.ready. The sidecar removes the .ready file, runs
// the Trivy client on LayoutDir@sha256:<hex>, writes the report to
// out/<hex>.json and then, last, the exit code to out/<hex>.exit. At start it
// writes `trivy version --format json` to version.json.
const (
	ScanReqDir      = "req"
	ScanOutDir      = "out"
	ScanCacheDir    = "cache"
	ScanVersionFile = "version.json"
	// JavaDBDir is where the Java DB is extracted, relative to ScanDir. Trivy
	// reads it from <cache dir>/java-db.
	JavaDBDir = ScanCacheDir + "/java-db"
)

// Environment of the scanner sidecar. The controller sets every value from
// the target's gate (platform input) and vuln.ReportTemplate; the script
// quotes them, so no value is ever parsed as shell.
const (
	ScannerURLEnv      = "TAGWARDEN_SCANNER_URL"
	ScannerTimeoutEnv  = "TAGWARDEN_SCANNER_TIMEOUT" // a Go duration, for example 10m0s
	ScannerJavaDBEnv   = "TAGWARDEN_JAVA_DB"         // Disabled or PerJob
	ScannerTemplateEnv = "TAGWARDEN_REPORT_TEMPLATE"
)

// SidecarScript is the fixed shell loop of the scanner sidecar, run with
// /bin/sh -c. It handles one request at a time and only names that are 64
// lower-case hex characters. The token comes from TRIVY_TOKEN. The hex check
// lists the characters: a range such as [0-9a-f] depends on the locale and
// can match upper case.
const SidecarScript = `set -u
cd /scan || exit 1
mkdir -p req out cache
trivy version --format json > version.json.tmp 2>/dev/null && mv -f version.json.tmp version.json
java='--skip-files=**/*.jar,**/*.war,**/*.ear,**/*.par'
if [ "$TAGWARDEN_JAVA_DB" = PerJob ]; then java='--cache-dir=/scan/cache'; fi
ca=''
if [ -f /var/run/tagwarden/scanner-ca/ca.crt ]; then ca='--cacert=/var/run/tagwarden/scanner-ca/ca.crt'; fi
while :; do
  for r in req/*.ready; do
    [ -f "$r" ] || continue
    h=${r#req/}
    h=${h%.ready}
    rm -f "$r"
    case $h in *[!0123456789abcdef]*) continue ;; esac
    [ ${#h} -eq 64 ] || continue
    trivy image --server "$TAGWARDEN_SCANNER_URL" --token-header Trivy-Token \
      --input "/work/layout@sha256:$h" --scanners vuln \
      --skip-db-update --skip-java-db-update --skip-version-check --disable-telemetry \
      --timeout "$TAGWARDEN_SCANNER_TIMEOUT" "$java" $ca \
      --format template --template "$TAGWARDEN_REPORT_TEMPLATE" > "out/$h.json"
    echo $? > "out/$h.exit.tmp"
    mv -f "out/$h.exit.tmp" "out/$h.exit"
  done
  sleep 1
done
`

// Gate scan error reasons and the run-level gate state, as in
// status.findings scanError and the VulnerabilityGate condition.
const (
	GateOK                 = "ok"
	GateDBStale            = "DBStale"
	GateScannerUnavailable = "ScannerUnavailable"
	GateVersionMismatch    = "VersionMismatch"
	GateScanFailed         = "ScanFailed"
)

// Gate is the vulnerability gate of a generated mirror, resolved by the
// controller to plain data. It holds no secret values.
type Gate struct {
	Action         v1alpha1.GateAction        `json:"action"`
	Severity       v1alpha1.SeverityThreshold `json:"severity"`
	IgnoreUnfixed  bool                       `json:"ignoreUnfixed,omitempty"`
	IncludeUnknown bool                       `json:"includeUnknown,omitempty"`
	OnScanError    v1alpha1.GateAction        `json:"onScanError"`
	MaxDBAge       metav1.Duration            `json:"maxDBAge"`
	Scanner        GateScanner                `json:"scanner"`
	// Exceptions are the active VulnerabilityExceptions for this mirror.
	Exceptions []GateException `json:"exceptions,omitempty"`
	// Judged lists the (tag, digest) pairs this mirror has a final verdict
	// for (passed, accepted or findings) from earlier gated runs, as the
	// Jobs reported them in Report.Judged. A tag on the target that is not
	// judged is scanned, so tags copied before the gate or during a scan
	// error are reported too. Never derive it from status.synced: a tag on
	// the target is not a tag that was judged.
	Judged []SyncedTag `json:"judged,omitempty"`
}

// GateScanner is the Trivy server and client of the gate.
type GateScanner struct {
	// URL is normalised by ScannerURL: a cluster Service host is
	// <svc>.<ns>.svc.<clusterDomain>. with a trailing dot.
	URL string `json:"url"`
	// InCluster means URL is a cluster Service name, so the pod and service
	// CIDRs may be dialled for it. Loopback, link-local and metadata
	// addresses are always refused.
	InCluster bool `json:"inCluster,omitempty"`
	// Version is the client version, pinned with Image. The server must
	// have the same major.minor.
	Version string `json:"version"`
	// Image is the client image, for the audit line only.
	Image   string              `json:"image,omitempty"`
	Timeout metav1.Duration     `json:"timeout"`
	JavaDB  v1alpha1.JavaDBMode `json:"javaDB"`
	// JavaDBRepository is <registry>/<repository>:<tag> in the target
	// registry, required with JavaDB PerJob.
	JavaDBRepository string `json:"javaDBRepository,omitempty"`
}

// GateException is one VulnerabilityException.
type GateException struct {
	Name            string      `json:"name"`
	Namespaces      []string    `json:"namespaces"`
	Repository      string      `json:"repository"`
	Digests         []string    `json:"digests,omitempty"`
	Vulnerabilities []string    `json:"vulnerabilities,omitempty"`
	Expires         metav1.Time `json:"expires"`
}

// ScannerDefaults are the manager's scanner settings for fields the target
// leaves empty.
type ScannerDefaults struct {
	URL, Version, Image string
}

// Gate defaults, as in the CRD.
const (
	DefaultMaxDBAge       = 72 * time.Hour
	DefaultScannerTimeout = 10 * time.Minute
)

// NewGate maps a target's gate, the manager defaults, the exceptions that
// apply to the mirror and the judged pairs onto the spec. It is the only
// place that reads the API gate types for the Job. The scanner URL is
// normalised with ScannerURL for clusterDomain, so the Job and the sidecar
// use the same host as the controller's probe.
func NewGate(g *v1alpha1.VulnerabilityGate, d ScannerDefaults, clusterDomain string, excs []v1alpha1.VulnerabilityException, judged []SyncedTag) (*Gate, error) {
	out := &Gate{
		Action: v1alpha1.GateActionReport, Severity: v1alpha1.SeverityThresholdCritical,
		IgnoreUnfixed: g.IgnoreUnfixed, IncludeUnknown: g.IncludeUnknown,
		OnScanError: v1alpha1.GateActionReport,
		MaxDBAge:    metav1.Duration{Duration: DefaultMaxDBAge},
		Scanner: GateScanner{
			URL: d.URL, Version: d.Version, Image: d.Image,
			Timeout: metav1.Duration{Duration: DefaultScannerTimeout},
			JavaDB:  v1alpha1.JavaDBDisabled,
		},
		Judged: judged,
	}
	if g.Action != "" {
		out.Action = g.Action
	}
	if g.Severity != "" {
		out.Severity = g.Severity
	}
	if g.OnScanError != "" {
		out.OnScanError = g.OnScanError
	}
	if g.MaxDBAge != nil {
		out.MaxDBAge = *g.MaxDBAge
	}
	if s := g.Scanner; s != nil {
		if s.URL != "" {
			out.Scanner.URL = s.URL
		}
		if s.Image != "" {
			out.Scanner.Image, out.Scanner.Version = s.Image, s.Version
		}
		if s.Timeout != nil {
			out.Scanner.Timeout = *s.Timeout
		}
		if s.JavaDB != "" {
			out.Scanner.JavaDB = s.JavaDB
		}
		out.Scanner.JavaDBRepository = s.JavaDBRepository
	}
	u, inCluster, err := ScannerURL(out.Scanner.URL, clusterDomain)
	if err != nil {
		return nil, fmt.Errorf("scanner url: %w", err)
	}
	out.Scanner.URL, out.Scanner.InCluster = u, inCluster
	for _, e := range excs {
		out.Exceptions = append(out.Exceptions, GateException{
			Name: e.Name, Namespaces: e.Spec.Namespaces, Repository: e.Spec.Repository,
			Digests: e.Spec.Digests, Vulnerabilities: e.Spec.Vulnerabilities, Expires: e.Spec.Expires,
		})
	}
	return out, nil
}

// Policy maps the gate onto the verdict policy.
func (g *Gate) Policy() vuln.Policy {
	sev, _ := vuln.ParseSeverity(string(g.Severity)) // validated by Decode
	return vuln.Policy{
		Action: vuln.Action(g.Action), Severity: sev,
		IgnoreUnfixed: g.IgnoreUnfixed, IncludeUnknown: g.IncludeUnknown,
		OnScanError: vuln.Action(g.OnScanError),
	}
}

// VulnExceptions maps the exceptions onto the verdict input.
func (g *Gate) VulnExceptions() []vuln.Exception {
	out := make([]vuln.Exception, 0, len(g.Exceptions))
	for _, e := range g.Exceptions {
		out = append(out, vuln.Exception{
			Name: e.Name, Namespaces: e.Namespaces, Repository: e.Repository,
			Digests: e.Digests, Vulnerabilities: e.Vulnerabilities, Expires: e.Expires.Time,
		})
	}
	return out
}

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	vulnIDPattern  = regexp.MustCompile(`^[A-Z]+-[0-9A-Za-z-]{1,64}$`)
)

// VulnID reports whether id fits the ID pattern of status and reports.
func VulnID(id string) bool { return vulnIDPattern.MatchString(id) }

func (g *Gate) validate(target name.Repository) error {
	for _, a := range []v1alpha1.GateAction{g.Action, g.OnScanError} {
		if a != v1alpha1.GateActionReport && a != v1alpha1.GateActionBlock {
			return fmt.Errorf("unknown action %q", a)
		}
	}
	if _, err := vuln.ParseSeverity(string(g.Severity)); err != nil {
		return err
	}
	if g.MaxDBAge.Duration <= 0 {
		return errors.New("maxDBAge: must be positive")
	}
	if err := g.Scanner.validate(target); err != nil {
		return fmt.Errorf("scanner.%w", err)
	}
	for _, e := range g.Exceptions {
		if e.Name == "" || len(e.Namespaces) == 0 || e.Repository == "" {
			return errors.New("exceptions: name, namespaces and repository are required")
		}
		for _, d := range e.Digests {
			if !digestPattern.MatchString(d) {
				return fmt.Errorf("exceptions: %s: invalid digest", e.Name)
			}
		}
	}
	for _, r := range g.Judged {
		if !tagPattern.MatchString(r.Tag) || !digestPattern.MatchString(r.Digest) {
			return errors.New("judged: invalid entry")
		}
	}
	return nil
}

func (s GateScanner) validate(target name.Repository) error {
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("url: must be an http or https URL without a path")
	}
	if !versionPattern.MatchString(s.Version) {
		return errors.New("version: must be <major>.<minor>.<patch>")
	}
	if s.Timeout.Duration <= 0 || s.Timeout.Duration > time.Hour {
		return errors.New("timeout: must be positive and at most 1h")
	}
	switch s.JavaDB {
	case v1alpha1.JavaDBDisabled:
	case v1alpha1.JavaDBPerJob:
		ref, err := name.NewTag(s.JavaDBRepository, name.StrictValidation)
		if err != nil {
			return fmt.Errorf("javaDBRepository: %w", err)
		}
		if CanonicalRegistry(ref.RegistryStr()) != CanonicalRegistry(target.RegistryStr()) {
			return errors.New("javaDBRepository: must be in the target registry")
		}
	default:
		return fmt.Errorf("javaDB: unknown value %q", s.JavaDB)
	}
	return nil
}
