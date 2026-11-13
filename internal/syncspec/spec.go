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
	"time"

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
	// AWSTokenFile is the projected ServiceAccount token with audience
	// AWSTokenAudience, mounted when a registry uses AWS workload identity.
	AWSTokenFile = "/var/run/tagwarden/aws-token/token" //nolint:gosec // path, not a credential
	// GCPTokenFile is the projected ServiceAccount token with the audience
	// of GCP.TokenAudience, mounted when a registry uses Google Cloud
	// workload identity.
	GCPTokenFile = "/var/run/tagwarden/gcp-token/token" //nolint:gosec // path, not a credential

	// ProxyUserEnv and ProxyPasswordEnv hold the proxy credentials. The
	// proxy itself comes from HTTPS_PROXY and NO_PROXY. Only these
	// uppercase names are read; proxy credentials without HTTPS_PROXY,
	// for example next to a lowercase https_proxy, are a config error.
	ProxyUserEnv     = "TAGWARDEN_PROXY_USER"
	ProxyPasswordEnv = "TAGWARDEN_PROXY_PASSWORD" //nolint:gosec // env var name, not a credential
)

// FlavorHarbor is Spec.TargetFlavor for Harbor: tags are deleted through
// the Harbor API.
const FlavorHarbor = "Harbor"

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
	// tokens, the documented public-cloud ACR audience. US Government and
	// China clouds are untested and may need another audience; there the
	// token request fails closed and no token leaks. A Resource Manager
	// scope would mint a management token and send it to the registry, so
	// no other scope is allowed.
	AzureScope = "https://containerregistry.azure.net/.default"

	// AuthAWSWorkloadIdentity names AWS IAM roles for service accounts in
	// Spec.TargetAuth and Spec.SourceAuth.
	AuthAWSWorkloadIdentity = "awsWorkloadIdentity"
	// AWSTokenAudience is the audience AWS STS expects in a ServiceAccount
	// token from an EKS or other IAM OIDC provider, in every partition.
	AWSTokenAudience = "sts.amazonaws.com" //nolint:gosec // audience, not a credential

	// AuthGCPWorkloadIdentity names Google Cloud Workload Identity
	// Federation in Spec.TargetAuth and Spec.SourceAuth.
	AuthGCPWorkloadIdentity = "gcpWorkloadIdentity"
	// GCPScope is the OAuth scope of federated tokens: cloud-platform is
	// used for federated tokens. Artifact Registry also accepts Cloud
	// Storage scopes, used for impersonated tokens (GCPImpersonatedScope).
	GCPScope = "https://www.googleapis.com/auth/cloud-platform"
	// GCPImpersonatedScope is the scope of service account access tokens,
	// enough to push to and pull from Artifact Registry.
	GCPImpersonatedScope = "https://www.googleapis.com/auth/devstorage.read_write"
)

// GCP is the Google Cloud Workload Identity Federation provider of a sync
// run. It holds identifiers only, no secrets.
type GCP struct {
	Audience            string `json:"audience"`
	ServiceAccountEmail string `json:"serviceAccountEmail,omitempty"`
}

var (
	gcpAudience = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
	gcpEmail    = regexp.MustCompile(`^[a-z0-9-]{6,30}@[a-z0-9-]{6,30}\.iam\.gserviceaccount\.com$`)
	garHost     = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*-docker\.pkg\.dev|((us|eu|asia)\.)?gcr\.io)(:443)?$`)
)

// TokenAudience is the audience of the projected ServiceAccount token: the
// default allowed audience of a workload identity pool provider.
func (g *GCP) TokenAudience() string { return "https:" + g.Audience }

func (g *GCP) validate() error {
	if !gcpAudience.MatchString(g.Audience) {
		return errors.New("audience must be a workload identity pool provider")
	}
	if g.ServiceAccountEmail != "" && !gcpEmail.MatchString(g.ServiceAccountEmail) {
		return errors.New("serviceAccountEmail must be a service account email")
	}
	return nil
}

// GARHost reports whether host is a Google Artifact Registry Docker host,
// <location>-docker.pkg.dev or a gcr.io domain that Artifact Registry
// serves. ASCII letters are folded as in the CRD rule.
func GARHost(host string) bool { return garHost.MatchString(lowerASCII(host)) }

// Azure is the Microsoft Entra workload identity of a sync run. It holds
// identifiers only, no secrets.
type Azure struct {
	ClientID      string `json:"clientID"`
	TenantID      string `json:"tenantID"`
	AuthorityHost string `json:"authorityHost"`
}

// AWS is the IAM role of a sync run. It holds identifiers only, no secrets.
type AWS struct {
	RoleARN string `json:"roleARN"`
	Region  string `json:"region"`
}

var (
	roleARN   = regexp.MustCompile(`^arn:aws(-cn|-us-gov)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,576}$`)
	awsRegion = regexp.MustCompile(`^((us|eu|ap|sa|ca|me|af|il|mx|cn)-[a-z]+|us-gov-[a-z]+)-[0-9]{1,2}$`)
	ecrHost   = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?(:443)?$`)
)

func (a *AWS) validate() error {
	if !roleARN.MatchString(a.RoleARN) || !awsRegion.MatchString(a.Region) {
		return errors.New("roleARN must be an IAM role ARN and region an AWS Region")
	}
	if strings.HasPrefix(a.RoleARN, "arn:aws-cn:") != strings.HasPrefix(a.Region, "cn-") ||
		strings.HasPrefix(a.RoleARN, "arn:aws-us-gov:") != strings.HasPrefix(a.Region, "us-gov-") {
		return errors.New("roleARN and region must be in the same AWS partition")
	}
	return nil
}

// ECRHost parses an Amazon ECR private registry host,
// <account>.dkr.ecr[-fips].<region>.amazonaws.com[.cn][:443]. It reports
// ok only when the DNS suffix fits the region: amazonaws.com.cn for China,
// amazonaws.com without FIPS in China otherwise. ASCII letters are folded
// as in the CRD rule.
func ECRHost(host string) (region string, fips, ok bool) {
	m := ecrHost.FindStringSubmatch(lowerASCII(host))
	if m == nil || !awsRegion.MatchString(m[2]) {
		return "", false, false
	}
	china := strings.HasPrefix(m[2], "cn-")
	if china != (m[3] != "") || china && m[1] != "" {
		return "", false, false
	}
	return m[2], m[1] != "", true
}

// AWSDNSSuffix is the DNS suffix of the AWS endpoints in region.
func AWSDNSSuffix(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}

func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

var (
	acrHost        = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)?\.azurecr\.(io|us|cn)(:443)?$`)
	azureAuthority = regexp.MustCompile(`^https://(login\.microsoftonline\.(com|us)|login\.partner\.microsoftonline\.cn|login\.chinacloudapi\.cn)/?$`)
)

// ACRHost reports whether host is an Azure Container Registry login
// server. Like CEL lowerAscii in the CRD rule, only ASCII letters are
// folded, so a non-ASCII look-alike such as the Kelvin sign never matches.
func ACRHost(host string) bool { return acrHost.MatchString(lowerASCII(host)) }

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

// Mirror names the ArtifactMirror a sync runs for, for audit lines, and
// its ClusterMirrorTarget.
type Mirror struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Target is the ClusterMirrorTarget name, for messages.
	Target string `json:"target,omitempty"`
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
	// TargetFlavor is the target's registryFlavor. Empty means OCI
	// distribution.
	TargetFlavor string `json:"targetFlavor,omitempty"`
	// Azure is required when a registry uses AuthAzureWorkloadIdentity.
	Azure *Azure `json:"azure,omitempty"`
	// AWS is required when a registry uses AuthAWSWorkloadIdentity.
	AWS *AWS `json:"aws,omitempty"`
	// GCP is required when a registry uses AuthGCPWorkloadIdentity.
	GCP *GCP `json:"gcp,omitempty"`

	// Prunable lists the tags the Job may delete from the target when the
	// selection no longer includes them, each with the digest the mirror
	// recorded. The controller sets it only with tags.prune on. Prune only
	// takes tags in this list and only while they still point at the
	// recorded digest.
	Prunable []SyncedTag `json:"prunable,omitempty"`

	// Gate is set for a gated generated mirror only. Without it the Job
	// runs exactly as an ungated one.
	Gate *Gate `json:"gate,omitempty"`

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
	if s.Gate != nil {
		if err := s.Gate.validate(s.TargetRepo); err != nil {
			return Spec{}, fmt.Errorf("spec: gate: %w", err)
		}
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
	if s.MaxTags < 0 || s.MaxTags > tags.MaxTagsLimit {
		return fmt.Errorf("maxTags: must be between 0 and %d", tags.MaxTagsLimit)
	}
	if s.MaxArtifactSize < 0 {
		return errors.New("maxArtifactSize: must not be negative")
	}
	if len(s.AllowedSources) == 0 || slices.Contains(s.AllowedSources, "") {
		return errors.New("allowedSources: at least one non-empty host is required")
	}
	if len(s.Prunable) > MaxPrunable {
		return fmt.Errorf("prunable: more than %d entries", MaxPrunable)
	}
	for _, p := range s.Prunable {
		if !tagPattern.MatchString(p.Tag) || !digestPattern.MatchString(p.Digest) {
			return errors.New("prunable: invalid entry")
		}
	}
	if err := s.validateAuth(); err != nil {
		return err
	}
	if err := s.validateFlavor(); err != nil {
		return err
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

// validateAuth checks the registry auth modes and their cloud settings.
func (s *Spec) validateAuth() error {
	for _, a := range []string{s.TargetAuth, s.SourceAuth} {
		switch a {
		case "":
		case AuthAzureWorkloadIdentity:
			if s.Azure == nil {
				return errors.New("azure: required by " + AuthAzureWorkloadIdentity)
			}
		case AuthAWSWorkloadIdentity:
			if s.AWS == nil {
				return errors.New("aws: required by " + AuthAWSWorkloadIdentity)
			}
		case AuthGCPWorkloadIdentity:
			if s.GCP == nil {
				return errors.New("gcp: required by " + AuthGCPWorkloadIdentity)
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
	if s.AWS != nil {
		if err := s.AWS.validate(); err != nil {
			return fmt.Errorf("aws: %w", err)
		}
	}
	if s.GCP != nil {
		if err := s.GCP.validate(); err != nil {
			return fmt.Errorf("gcp: %w", err)
		}
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

// Report versions. Ungated Jobs write ReportVersion as before; gated Jobs
// write ReportVersionGate, which adds the gate fields.
const (
	ReportVersion     = 1
	ReportVersionGate = 2
)

// SyncedTag is a tag on the target and the digest it was copied by.
type SyncedTag struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	// Copied is set in Report.Synced for a tag this run copied or
	// overwrote. A skipped tag was already on the target, so the mirror
	// cannot show it put the tag there and does not own it.
	Copied bool `json:"copied,omitempty"`
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

	// Version 2. Counts of tags per verdict, and of tags the gate did not
	// copy.
	Findings   int `json:"findings,omitempty"`
	Accepted   int `json:"accepted,omitempty"`
	ScanErrors int `json:"scanErrors,omitempty"`
	Blocked    int `json:"blocked,omitempty"`
	// Gate is the run-level scanner check: GateOK or a scan error reason.
	// Empty when the run had nothing to scan.
	Gate string `json:"gate,omitempty"`
	// JavaScanned is set on every gated run.
	JavaScanned *bool `json:"javaScanned,omitempty"`
	// TagFindings lists the tags with verdict findings or scan-error,
	// newest first. FindingsTruncated means it was cut to fit.
	TagFindings       []TagFinding `json:"tagFindings,omitempty"`
	FindingsTruncated bool         `json:"findingsTruncated,omitempty"`
	// Judged lists the tags this run gave a final verdict (passed,
	// accepted or findings), never scan errors. The controller keeps them
	// in a status field of their own and passes them back in Gate.Judged.
	// JudgedTruncated means it was cut; the cut tags are scanned again.
	Judged          []SyncedTag `json:"judged,omitempty"`
	JudgedTruncated bool        `json:"judgedTruncated,omitempty"`
	// AcceptedBy lists, per tag and exception, the IDs the exception let
	// through. The controller turns new entries into
	// VulnerabilityExceptionApplied Events.
	AcceptedBy []TagAccepted `json:"acceptedBy,omitempty"`
	// JudgedFingerprint is Gate.Fingerprint of the run, set on every gated
	// run. The controller stores it with Judged and passes it back in
	// Gate.JudgedFingerprint.
	JudgedFingerprint string `json:"judgedFingerprint,omitempty"`
	// Rescan marks the report of a re-scan Job: the tags were read from
	// the target and nothing was copied. Its tag findings carry
	// RescanAction.
	Rescan bool `json:"rescan,omitempty"`

	// Pruned lists the Spec.Prunable tags the Job deleted from the target.
	// Dropped lists the ones it found gone or moved and left alone; the
	// controller stops tracking them. PrunedTruncated means the lists were
	// cut to fit the message: the cut tags are checked again next run.
	Pruned          []SyncedTag `json:"pruned,omitempty"`
	Dropped         []SyncedTag `json:"dropped,omitempty"`
	PrunedTruncated bool        `json:"prunedTruncated,omitempty"`

	// Selection says what the tag selection did. Nil in a re-scan and from
	// Jobs that predate it; the controller then judges nothing from it.
	Selection *Selection `json:"selection,omitempty"`
}

// MaxPrunable caps Spec.Prunable, as status.owned.
const MaxPrunable = 200

// MaxMissingTags caps Selection.MissingTags.
const MaxMissingTags = 5

// Selection counts the tags each filter removed, as tags.Stats.
type Selection struct {
	Listed     int `json:"listed,omitempty"`
	Filtered   int `json:"filtered,omitempty"`
	NotSemver  int `json:"notSemver,omitempty"`
	Prerelease int `json:"prerelease,omitempty"`
	OutOfRange int `json:"outOfRange,omitempty"`
	Trimmed    int `json:"trimmed,omitempty"`
	Selected   int `json:"selected"`
	// Missing counts explicit tags not found upstream; MissingTags names
	// the first MaxMissingTags of them, and none when they do not fit.
	Missing     int      `json:"missing,omitempty"`
	MissingTags []string `json:"missingTags,omitempty"`
}

// TagFinding is the gate result of one tag with findings or a scan error.
type TagFinding struct {
	Tag             string                  `json:"tag"`
	Digest          string                  `json:"digest"`
	Verdict         v1alpha1.FindingVerdict `json:"verdict"`
	Outcome         v1alpha1.FindingOutcome `json:"outcome"`
	PresentOnTarget bool                    `json:"presentOnTarget,omitempty"`
	Severity        v1alpha1.Severity       `json:"severity,omitempty"`
	Counts          v1alpha1.SeverityCounts `json:"counts,omitzero"`
	// TopIDs are up to MaxReportIDs IDs, worst first.
	TopIDs    []string `json:"topIDs,omitempty"`
	ScanError string   `json:"scanError,omitempty"`
	// DBUpdatedAt is the server DB time, RFC 3339, when the server was checked.
	DBUpdatedAt string    `json:"dbUpdatedAt,omitempty"`
	ScannedAt   time.Time `json:"scannedAt"`
	// RescanAction is set in a re-scan report for verdict findings only.
	RescanAction v1alpha1.VulnerableTagAction `json:"rescanAction,omitempty"`
}

// MaxReportIDs caps TagFinding.TopIDs.
const MaxReportIDs = 3

// TagAccepted is the use of one exception on one tag.
type TagAccepted struct {
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
	Exception string `json:"exception"`
	// IDs are up to MaxAcceptedIDs IDs the exception covers on the tag.
	IDs []string `json:"ids"`
}

// MaxAcceptedIDs caps TagAccepted.IDs and the entries of a report.
const MaxAcceptedIDs = 10

// MaxAcceptedEntries caps Report.AcceptedBy, as status.gate.accepted is capped.
const MaxAcceptedEntries = 200

var exceptionNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Valid reports whether ParseReport accepts a.
func (a TagAccepted) Valid() bool { return a.validate() == nil }

func (a TagAccepted) validate() error {
	if !tagPattern.MatchString(a.Tag) || !digestPattern.MatchString(a.Digest) ||
		len(a.Exception) > 253 || !exceptionNamePattern.MatchString(a.Exception) {
		return errors.New("tag, digest or exception")
	}
	if len(a.IDs) > MaxAcceptedIDs || slices.ContainsFunc(a.IDs, func(id string) bool { return !VulnID(id) }) {
		return errors.New("ids")
	}
	return nil
}

// maxReportClockSkew is how far in the future a report time may be.
const maxReportClockSkew = 5 * time.Minute

var (
	tagPattern    = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// ValidTag reports whether t is a valid OCI tag.
func ValidTag(t string) bool { return tagPattern.MatchString(t) }

// ParseReport decodes a termination message. The message comes from the
// Job, so it is untrusted: it must fit MaxReportSize, have version
// ReportVersion or ReportVersionGate, non-negative counts and valid tags,
// digests and gate fields. Unknown fields are ignored so that a newer Job
// can add some.
func ParseReport(msg string) (Report, error) {
	if len(msg) > MaxReportSize {
		return Report{}, fmt.Errorf("report: larger than %d bytes", MaxReportSize)
	}
	var r Report
	if err := json.Unmarshal([]byte(msg), &r); err != nil {
		return Report{}, errors.New("report: not valid JSON")
	}
	if r.V != ReportVersion && r.V != ReportVersionGate {
		return Report{}, fmt.Errorf("report: version %d, want %d or %d", r.V, ReportVersion, ReportVersionGate)
	}
	if min(r.Copied, r.Skipped, r.Mutated, r.Failed, r.Findings, r.Accepted, r.ScanErrors, r.Blocked) < 0 {
		return Report{}, errors.New("report: negative count")
	}
	for _, s := range r.Synced {
		if !tagPattern.MatchString(s.Tag) || !digestPattern.MatchString(s.Digest) {
			return Report{}, errors.New("report: invalid synced entry")
		}
	}
	if err := validateSelection(r.Selection); err != nil {
		return Report{}, err
	}
	if err := validatePruneFields(r); err != nil {
		return Report{}, err
	}
	if r.V == ReportVersion && (r.Findings+r.Accepted+r.ScanErrors+r.Blocked > 0 || r.Gate != "" || r.JavaScanned != nil || len(r.TagFindings) > 0 || len(r.Judged) > 0 || len(r.AcceptedBy) > 0 || r.JudgedFingerprint != "" || r.Rescan) {
		return Report{}, errors.New("report: gate fields in version 1")
	}
	switch r.Gate {
	case "", GateOK, GateDBStale, GateScannerUnavailable, GateVersionMismatch:
	default:
		return Report{}, errors.New("report: invalid gate")
	}
	for _, f := range r.TagFindings {
		if err := f.validate(r.Rescan); err != nil {
			return Report{}, fmt.Errorf("report: invalid tag finding: %w", err)
		}
	}
	if len(r.AcceptedBy) > MaxAcceptedEntries {
		return Report{}, errors.New("report: too many accepted entries")
	}
	for _, a := range r.AcceptedBy {
		if err := a.validate(); err != nil {
			return Report{}, fmt.Errorf("report: invalid accepted entry: %w", err)
		}
	}
	return r, nil
}

func validateSelection(sel *Selection) error {
	if sel == nil {
		return nil
	}
	if min(sel.Listed, sel.Filtered, sel.NotSemver, sel.Prerelease, sel.OutOfRange, sel.Trimmed, sel.Selected, sel.Missing) < 0 {
		return errors.New("report: negative count")
	}
	if len(sel.MissingTags) > MaxMissingTags {
		return errors.New("report: invalid selection")
	}
	for _, t := range sel.MissingTags {
		if !tagPattern.MatchString(t) {
			return errors.New("report: invalid selection")
		}
	}

	return nil
}

func validatePruneFields(r Report) error {
	if len(r.Pruned) > MaxPrunable || len(r.Dropped) > MaxPrunable || r.Rescan && len(r.Pruned)+len(r.Dropped) > 0 {
		return errors.New("report: invalid pruned entries")
	}
	for _, s := range slices.Concat(r.Pruned, r.Dropped) {
		if !tagPattern.MatchString(s.Tag) || !digestPattern.MatchString(s.Digest) {
			return errors.New("report: invalid pruned entry")
		}
	}
	for _, s := range r.Judged {
		if !tagPattern.MatchString(s.Tag) || !digestPattern.MatchString(s.Digest) {
			return errors.New("report: invalid judged entry")
		}
	}
	if r.JudgedFingerprint != "" && !fingerprintPattern.MatchString(r.JudgedFingerprint) {
		return errors.New("report: invalid judged fingerprint")
	}
	return nil
}

var clusterServiceName = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\.svc)(\.cluster\.local)?$`)

// ScannerURL returns the Trivy server URL that the controller probes and
// gated Jobs use, with the host as a fully qualified name (trailing dot),
// so resolv.conf search domains are never tried first: with ndots 5,
// <svc>.<ns>.svc would otherwise resolve as <svc>.<ns>.svc.svc.<domain>
// in a tenant namespace named svc. A cluster Service name
// (<svc>.<ns>.svc, optionally with .cluster.local or .<clusterDomain>)
// becomes <svc>.<ns>.svc.<clusterDomain>. and inCluster is true. IP
// addresses are left as they are.
func ScannerURL(raw, clusterDomain string) (string, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, err
	}
	host := strings.TrimSuffix(lowerASCII(u.Hostname()), ".")
	if host == "" {
		return "", false, errors.New("scanner URL has no host")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return u.String(), false, nil
	}
	domain := strings.Trim(lowerASCII(clusterDomain), ".")
	inCluster := false
	if m := clusterServiceName.FindStringSubmatch(strings.TrimSuffix(host, "."+domain)); m != nil {
		host, inCluster = m[1]+"."+domain, true
	}
	host += "."
	if p := u.Port(); p != "" {
		host += ":" + p
	}
	u.Host = host
	return u.String(), inCluster, nil
}

func (f TagFinding) validate(rescan bool) error {
	if !tagPattern.MatchString(f.Tag) || !digestPattern.MatchString(f.Digest) {
		return errors.New("tag or digest")
	}
	switch {
	case f.Verdict == v1alpha1.VerdictFindings && f.ScanError == "":
	case f.Verdict == v1alpha1.VerdictScanError && slices.Contains([]string{GateDBStale, GateScannerUnavailable, GateVersionMismatch, GateScanFailed}, f.ScanError):
	default:
		return errors.New("verdict")
	}
	if f.Outcome != v1alpha1.OutcomeCopied && f.Outcome != v1alpha1.OutcomeBlocked {
		return errors.New("outcome")
	}
	switch f.Severity {
	case "", v1alpha1.SeverityCritical, v1alpha1.SeverityHigh, v1alpha1.SeverityMedium, v1alpha1.SeverityLow, v1alpha1.SeverityUnknown:
	default:
		return errors.New("severity")
	}
	c := f.Counts
	if min(c.Critical, c.High, c.Medium, c.Low, c.Unknown) < 0 {
		return errors.New("negative count")
	}
	if len(f.TopIDs) > MaxReportIDs || slices.ContainsFunc(f.TopIDs, func(id string) bool { return !VulnID(id) }) {
		return errors.New("topIDs")
	}
	// Status requires scannedAt; a zero time would make every status update
	// of the mirror fail.
	if f.ScannedAt.IsZero() || f.ScannedAt.After(time.Now().Add(maxReportClockSkew)) {
		return errors.New("scannedAt")
	}
	if f.DBUpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339, f.DBUpdatedAt); err != nil {
			return errors.New("dbUpdatedAt")
		}
	}
	switch {
	case !rescan || f.Verdict != v1alpha1.VerdictFindings:
		if f.RescanAction != "" {
			return errors.New("rescanAction")
		}
	case !slices.Contains([]v1alpha1.VulnerableTagAction{v1alpha1.VulnerableKept, v1alpha1.VulnerableUntagged,
		v1alpha1.VulnerableUntagFailed, v1alpha1.VulnerableUntagRefused}, f.RescanAction):
		return errors.New("rescanAction")
	}
	return nil
}

// validateFlavor checks TargetFlavor. Harbor tag deletes use basic auth
// from the target Secret, so cloud TargetAuth is refused.
func (s *Spec) validateFlavor() error {
	switch s.TargetFlavor {
	case "":
	case FlavorHarbor:
		if s.TargetAuth != "" {
			return errors.New("targetFlavor Harbor: needs the target Secret credentials")
		}
	default:
		return fmt.Errorf("unknown targetFlavor %q", s.TargetFlavor)
	}
	return nil
}
