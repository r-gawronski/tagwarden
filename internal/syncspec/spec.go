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

// Package syncspec is the contract between the controller and the sync Job:
// the JSON spec the controller renders into a ConfigMap and the fixed paths
// where the Job finds its mounted files.
package syncspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/r-gawronski/tagwarden/api/v1alpha1"
	"github.com/r-gawronski/tagwarden/internal/tags"
)

// Fixed paths and environment variables in the sync Job pod.
const (
	// SpecFile is the default location of the mounted spec.
	SpecFile = "/etc/tagwarden/spec.json"
	// TargetAuthFile is the target push credentials as a dockerconfigjson.
	TargetAuthFile = "/var/run/tagwarden/target/.dockerconfigjson"
	// TargetCAFile is an optional CA bundle for the target registry.
	TargetCAFile = "/var/run/tagwarden/target-ca/ca.crt"
	// SourceAuthFile is the optional pull credentials for the source
	// registry as a dockerconfigjson.
	SourceAuthFile = "/var/run/tagwarden/source/.dockerconfigjson"
	// SourceCAFile is an optional CA bundle trusted for the source registry.
	SourceCAFile = "/var/run/tagwarden/source-ca/ca.crt"
	// ProxyCAFile is an optional CA bundle for a TLS-inspecting proxy.
	ProxyCAFile = "/var/run/tagwarden/proxy-ca/ca.crt"
	// ClientCertDir optionally holds tls.crt and tls.key for target mTLS.
	ClientCertDir = "/var/run/tagwarden/client-cert"
	// AzureTokenFile is the projected ServiceAccount token with audience
	// AzureTokenAudience, mounted when a registry uses Azure workload identity.
	AzureTokenFile = "/var/run/tagwarden/azure-token/token" //nolint:gosec // path, not a credential

	// ProxyUserEnv and ProxyPasswordEnv hold the proxy credentials. The
	// proxy itself comes from HTTPS_PROXY and NO_PROXY. Only these
	// uppercase names are read; proxy credentials without HTTPS_PROXY,
	// for example next to a lowercase https_proxy, are a config error.
	ProxyUserEnv     = "TAGWARDEN_PROXY_USER"
	ProxyPasswordEnv = "TAGWARDEN_PROXY_PASSWORD" //nolint:gosec // env var name, not a credential
)

// Cloud registry auth.
const (
	// AuthAzureWorkloadIdentity names Azure workload identity in
	// Spec.TargetAuth and Spec.SourceAuth.
	AuthAzureWorkloadIdentity = "azureWorkloadIdentity"
	// AzureTokenAudience is the audience Microsoft Entra ID expects in a
	// federated ServiceAccount token.
	AzureTokenAudience = "api://AzureADTokenExchange" //nolint:gosec // audience, not a credential
	// DefaultAzureAuthorityHost is the Microsoft Entra endpoint of the
	// global Azure cloud.
	DefaultAzureAuthorityHost = "https://login.microsoftonline.com/"
	// AzureScope is the Microsoft Entra scope of Azure Container Registry
	// tokens in every cloud. A Resource Manager scope would mint a
	// management token and send it to the registry, so no other is allowed.
	AzureScope = "https://containerregistry.azure.net/.default"
)

// Azure is the Microsoft Entra workload identity of a sync run. It holds
// identifiers only, no secrets.
type Azure struct {
	ClientID      string `json:"clientID"`
	TenantID      string `json:"tenantID"`
	AuthorityHost string `json:"authorityHost"`
}

var (
	acrHost        = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)?\.azurecr\.(io|us|cn)(:443)?$`)
	azureAuthority = regexp.MustCompile(`^https://(login\.microsoftonline\.(com|us)|login\.partner\.microsoftonline\.cn|login\.chinacloudapi\.cn)/?$`)
)

// ACRHost reports whether host is an Azure Container Registry login
// server. Like CEL lowerAscii in the CRD rule, only ASCII letters are
// folded, so a non-ASCII look-alike such as the Kelvin sign never matches.
func ACRHost(host string) bool {
	return acrHost.MatchString(strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, host))
}

// AzureAuthority reports whether u is a known Microsoft Entra authority
// host. The CRD has the same rule; a new cloud needs both changed.
func AzureAuthority(u string) bool { return azureAuthority.MatchString(u) }

var guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (a *Azure) validate() error {
	if !guid.MatchString(a.ClientID) || !guid.MatchString(a.TenantID) {
		return errors.New("clientID and tenantID must be GUIDs")
	}
	u, err := url.Parse(a.AuthorityHost)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("authorityHost must be an https URL")
	}
	return nil
}

// Exit codes of the sync Job. The Job never returns 2 itself: the Go runtime
// exits 2 on an unrecovered crash, such as a panic outside the recovered
// code or a fatal runtime error. The controller treats 2 as a crash and
// lets the next run retry.
const (
	// ExitOK means every selected tag is on the target.
	ExitOK = 0
	// ExitSyncFailed means a tag failed, a mutation was refused or a
	// transient error stopped the run. The next run may succeed.
	ExitSyncFailed = 1
	// ExitConfig means the spec, the mounted files or the source checks
	// refused the run. It fails again until the configuration changes.
	ExitConfig = 3
)

// Mirror names the ArtifactMirror a sync runs for, for audit lines.
type Mirror struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Spec is one sync run.
type Spec struct {
	Mirror Mirror `json:"mirror"`
	// Source is registry/repository, with an explicit registry.
	Source string `json:"source"`
	// Target is registry/project/path.
	Target            string                 `json:"target"`
	Tags              tags.Policy            `json:"tags"`
	RequiredPlatforms []string               `json:"requiredPlatforms,omitempty"`
	OnTagMutation     v1alpha1.OnTagMutation `json:"onTagMutation"`
	// MaxTags caps the upstream listing. Zero means tags.MaxTags.
	MaxTags int `json:"maxTags,omitempty"`
	// MaxArtifactSize caps the config and layer bytes of one artifact.
	// Zero means no limit.
	MaxArtifactSize int64 `json:"maxArtifactSize,omitempty"`

	// AllowedSources are the registry hosts, as host[:port], that the
	// ClusterMirrorTarget allows. The Job re-checks Source against them.
	AllowedSources []string `json:"allowedSources"`
	// DeniedCIDRs are refused as source addresses on top of loopback,
	// link-local and metadata addresses, for example the cluster pod and
	// service CIDRs.
	DeniedCIDRs []string `json:"deniedCIDRs,omitempty"`

	// TargetAuth and SourceAuth name the cloud provider that authenticates
	// to the registry, such as AuthAzureWorkloadIdentity. Empty means the
	// mounted dockerconfigjson, or anonymous for a source without one.
	TargetAuth string `json:"targetAuth,omitempty"`
	SourceAuth string `json:"sourceAuth,omitempty"`
	// Azure is required when a registry uses AuthAzureWorkloadIdentity.
	Azure *Azure `json:"azure,omitempty"`

	// SourceRepo, TargetRepo and DeniedPrefixes are set by Decode.
	SourceRepo     name.Repository `json:"-"`
	TargetRepo     name.Repository `json:"-"`
	DeniedPrefixes []netip.Prefix  `json:"-"`
}

// Decode reads and validates a spec. Unknown fields are rejected, so a
// controller and Job of different versions fail loudly instead of silently
// dropping a field.
func Decode(r io.Reader) (Spec, error) {
	var s Spec
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("spec: %w", err)
	}
	if d.More() {
		return Spec{}, errors.New("spec: trailing data after the JSON object")
	}
	if err := s.validate(); err != nil {
		return Spec{}, fmt.Errorf("spec: %w", err)
	}
	return s, nil
}

func (s *Spec) validate() error {
	if s.Mirror.Namespace == "" || s.Mirror.Name == "" {
		return errors.New("mirror namespace and name are required")
	}
	var err error
	if s.SourceRepo, err = name.NewRepository(s.Source, name.StrictValidation); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if s.TargetRepo, err = name.NewRepository(s.Target, name.StrictValidation); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if err := tags.Validate(s.Tags); err != nil {
		return fmt.Errorf("tags: %w", err)
	}
	for _, p := range s.RequiredPlatforms {
		if _, err := v1.ParsePlatform(p); err != nil {
			return fmt.Errorf("requiredPlatforms: %q: %w", p, err)
		}
	}
	switch s.OnTagMutation {
	case v1alpha1.OnTagMutationFail, v1alpha1.OnTagMutationOverwrite, v1alpha1.OnTagMutationIgnore:
	default:
		return fmt.Errorf("onTagMutation: unknown value %q", s.OnTagMutation)
	}
	if s.MaxTags < 0 {
		return errors.New("maxTags: must not be negative")
	}
	if s.MaxArtifactSize < 0 {
		return errors.New("maxArtifactSize: must not be negative")
	}
	if len(s.AllowedSources) == 0 || slices.Contains(s.AllowedSources, "") {
		return errors.New("allowedSources: at least one non-empty host is required")
	}
	for _, a := range []string{s.TargetAuth, s.SourceAuth} {
		switch a {
		case "":
		case AuthAzureWorkloadIdentity:
			if s.Azure == nil {
				return errors.New("azure: required by " + AuthAzureWorkloadIdentity)
			}
		default:
			return fmt.Errorf("unknown registry auth %q", a)
		}
	}
	if s.Azure != nil {
		if err := s.Azure.validate(); err != nil {
			return fmt.Errorf("azure: %w", err)
		}
	}
	for _, c := range s.DeniedCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("deniedCIDRs: %w", err)
		}
		s.DeniedPrefixes = append(s.DeniedPrefixes, p)
	}
	return nil
}

// dockerHub lists the names of the same registry, canonical name first.
var dockerHub = []string{"docker.io", "index.docker.io", "registry-1.docker.io"}

// CanonicalRegistry lowercases host and maps the Docker Hub names to
// docker.io.
func CanonicalRegistry(host string) string {
	host = strings.ToLower(host)
	if slices.Contains(dockerHub, host) {
		return dockerHub[0]
	}
	return host
}

// AllowedSource reports whether host matches an allowed host[:port] exactly,
// ignoring case and treating the Docker Hub names as one registry.
func AllowedSource(host string, allowed []string) bool {
	return slices.ContainsFunc(allowed, func(a string) bool { return CanonicalRegistry(a) == CanonicalRegistry(host) })
}

var (
	// metadataAddrs are cloud metadata endpoints outside the link-local range.
	metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}
	// thisNetwork is 0.0.0.0/8, which some stacks route to the local host.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	// nat64 embeds an IPv4 address in its last four bytes.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// CheckAddr refuses loopback, link-local, unspecified and metadata
// addresses, 0.0.0.0/8, NAT64 addresses that embed any of these, and any
// address in denied.
func CheckAddr(a netip.Addr, denied []netip.Prefix) error {
	a = a.Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		if err := CheckAddr(netip.AddrFrom4([4]byte(b[12:])), denied); err != nil {
			return err
		}
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || thisNetwork.Contains(a) || slices.Contains(metadataAddrs, a) {
		return fmt.Errorf("resolves to internal address %s", a)
	}
	for _, p := range denied {
		if p.Contains(a) {
			return fmt.Errorf("resolves to %s in denied CIDR %s", a, p)
		}
	}
	return nil
}

// AuthKeyHost turns a dockerconfigjson auths key such as https://host/v1/
// into host.
func AuthKeyHost(key string) string {
	key = strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")
	host, _, _ := strings.Cut(key, "/")
	return host
}

// MaxReportSize is the Kubernetes limit for a termination message.
const MaxReportSize = 4096

// ReportVersion is the version of Report.
const ReportVersion = 1

// SyncedTag is a tag on the target and the digest it was copied by.
type SyncedTag struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

// Report is the termination message of a sync Job.
type Report struct {
	V       int `json:"v"`
	Copied  int `json:"copied"`
	Skipped int `json:"skipped"`
	Mutated int `json:"mutated"`
	Failed  int `json:"failed"`
	// Synced lists the selected tags on the target, newest first.
	Synced          []SyncedTag `json:"synced"`
	Errors          []string    `json:"errors,omitempty"`
	ErrorsTruncated bool        `json:"errorsTruncated,omitempty"`
	// Truncated means Synced was cut to fit the message.
	Truncated bool `json:"truncated,omitempty"`
}

var (
	tagPattern    = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// ParseReport decodes a termination message. The message comes from the
// Job, so it is untrusted: it must fit MaxReportSize, have version
// ReportVersion, non-negative counts and valid tags and digests. Unknown
// fields are ignored so that a newer Job can add some.
func ParseReport(msg string) (Report, error) {
	if len(msg) > MaxReportSize {
		return Report{}, fmt.Errorf("report: larger than %d bytes", MaxReportSize)
	}
	var r Report
	if err := json.Unmarshal([]byte(msg), &r); err != nil {
		return Report{}, errors.New("report: not valid JSON")
	}
	if r.V != ReportVersion {
		return Report{}, fmt.Errorf("report: version %d, want %d", r.V, ReportVersion)
	}
	if min(r.Copied, r.Skipped, r.Mutated, r.Failed) < 0 {
		return Report{}, errors.New("report: negative count")
	}
	for _, s := range r.Synced {
		if !tagPattern.MatchString(s.Tag) || !digestPattern.MatchString(s.Digest) {
			return Report{}, errors.New("report: invalid synced entry")
		}
	}
	return r, nil
}
