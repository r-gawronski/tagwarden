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

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mirrorv1alpha1 "github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

const (
	// scannerProbeInterval is how often the controller asks a Trivy
	// server for /version, per server URL and CA.
	scannerProbeInterval = time.Minute
	scannerProbeTimeout  = 10 * time.Second
	maxVersionBody       = 64 << 10
	defaultMaxDBAge      = 72 * time.Hour
)

// ScannerConfig is the Trivy server and client of the vulnerability gate.
// The manager's --trivy-url, --trivy-image and --trivy-version flags fill
// it for the in-chart server.
type ScannerConfig struct {
	URL, Image, Version string
}

// gateOf returns the vulnerability gate of t, or nil when it is off.
func gateOf(t *mirrorv1alpha1.ClusterMirrorTarget) *mirrorv1alpha1.VulnerabilityGate {
	if am := t.Spec.AutoMirror; am != nil && am.VulnerabilityGate != nil && am.VulnerabilityGate.Enabled {
		return am.VulnerabilityGate
	}
	return nil
}

// effectiveScanner overlays the set fields of s on the manager defaults.
// It returns a message when the result is not usable.
func effectiveScanner(s *mirrorv1alpha1.ScannerSpec, defaults ScannerConfig) (ScannerConfig, string) {
	c := defaults
	if s != nil {
		if s.URL != "" {
			c.URL = s.URL
		}
		if s.Image != "" {
			c.Image = s.Image
		}
		if s.Version != "" {
			c.Version = s.Version
		}
	}
	switch {
	case c.URL == "":
		return c, "not configured: set scanner.url or enable the chart's Trivy server"
	case c.Image == "" || c.Version == "":
		return c, "not configured: set scanner.image and scanner.version or enable the chart's Trivy server"
	}
	return c, ""
}

// versionMismatch returns a message when the server version got does not
// have the major and minor version of the client version want.
func versionMismatch(want, got string) string {
	w, err := semver.StrictNewVersion(want)
	if err != nil {
		return fmt.Sprintf("invalid client version %q", want)
	}
	g, err := semver.NewVersion(got)
	if err != nil {
		return fmt.Sprintf("server reports an invalid version, want %d.%d.x", w.Major(), w.Minor())
	}
	if g.Major() != w.Major() || g.Minor() != w.Minor() {
		return fmt.Sprintf("version %s, want %d.%d.x", g, w.Major(), w.Minor())
	}
	return ""
}

// dbMetadata is the DB block of the Trivy /version response.
type dbMetadata struct {
	Version      int
	NextUpdate   time.Time
	UpdatedAt    time.Time
	DownloadedAt time.Time
}

// versionInfo is the Trivy /version response. JavaDB and CheckBundle are
// optional fields newer servers may send; they are not used.
type versionInfo struct {
	Version         string
	VulnerabilityDB *dbMetadata
	JavaDB          *dbMetadata
	CheckBundle     json.RawMessage
}

// decodeVersion parses a /version body: one JSON object with known fields
// only and a version.
func decodeVersion(b []byte) (*versionInfo, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var v versionInfo
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid /version response: %w", err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid /version response: data after the JSON object")
	}
	if v.Version == "" {
		return nil, errors.New("invalid /version response: no Version")
	}
	return &v, nil
}

var clusterServiceHost = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\.svc(\.cluster\.local)?$`)

// scannerAddrCheck returns the dial check for a scanner host. Loopback,
// link-local and metadata addresses are always refused. The denied CIDRs
// (the cluster pod and service CIDRs) are refused unless the host is a
// cluster Service name, like the in-chart server, which lives there.
func scannerAddrCheck(host string, denied []netip.Prefix, allowLoopback bool) func(netip.Addr) error {
	if clusterServiceHost.MatchString(host) {
		denied = nil
	}
	return func(a netip.Addr) error {
		if allowLoopback && a.Unmap().IsLoopback() {
			return nil
		}
		return syncspec.CheckAddr(a, denied)
	}
}

// probeScanner calls GET <base>/version. It sends no credentials, follows
// no redirects, uses no proxy and dials only addresses check accepts.
func probeScanner(ctx context.Context, base string, caPEM []byte, check func(netip.Addr) error) (*versionInfo, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if len(caPEM) > 0 && !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA bundle holds no PEM certificate")
	}
	u, err := url.JoinPath(base, "version")
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: scannerProbeTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		return check(ap.Addr())
	}}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: scannerProbeTimeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(ctx, scannerProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionBody+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	if len(b) > maxVersionBody {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", u, maxVersionBody)
	}
	return decodeVersion(b)
}

// scannerConditions turns a probe result into the ScannerReady and
// VulnerabilityDBReady conditions. problem is a not-configured or Secret
// message that stopped the probe.
func scannerConditions(c ScannerConfig, problem string, info *versionInfo, probeErr error, maxAge time.Duration, now time.Time) (metav1.Condition, metav1.Condition) {
	sc := metav1.Condition{Type: ConditionScannerReady, Status: metav1.ConditionFalse, Reason: ReasonScannerUnavailable}
	db := metav1.Condition{Type: ConditionVulnerabilityDBReady, Status: metav1.ConditionUnknown, Reason: ReasonScannerUnavailable,
		Message: "the scanner did not answer"}
	switch {
	case problem != "":
		sc.Message = problem
		return sc, db
	case probeErr != nil:
		sc.Message = "unreachable: " + probeErr.Error()
		return sc, db
	}
	if msg := versionMismatch(c.Version, info.Version); msg != "" {
		sc.Reason, sc.Message = ReasonVersionMismatch, msg
	} else {
		sc.Status, sc.Reason, sc.Message = metav1.ConditionTrue, ReasonReady, fmt.Sprintf("Trivy %s at %s", info.Version, c.URL)
	}
	db.Status, db.Reason = metav1.ConditionFalse, ReasonDBStale
	switch {
	case info.VulnerabilityDB == nil || info.VulnerabilityDB.UpdatedAt.IsZero():
		db.Message = "the server reports no vulnerability DB"
	case now.Sub(info.VulnerabilityDB.UpdatedAt) > maxAge:
		db.Message = fmt.Sprintf("vulnerability DB updated %s, older than maxDBAge %s",
			info.VulnerabilityDB.UpdatedAt.UTC().Format(time.RFC3339), maxAge)
	default:
		db.Status, db.Reason = metav1.ConditionTrue, ReasonReady
		db.Message = "vulnerability DB updated " + info.VulnerabilityDB.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return sc, db
}
