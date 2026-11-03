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

// Package synccmd implements the sync subcommand that sync Jobs run. It
// never calls the Kubernetes API: it reads the spec and mounted files,
// writes one audit line per artifact to stdout and reports the result in
// the termination message.
package synccmd

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	stdsync "sync"
	"time"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/sync"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// TerminationLogPath is where Kubernetes reads the termination message.
const TerminationLogPath = "/dev/termination-log"

// maxTermination is the Kubernetes limit for a termination message.
const maxTermination = syncspec.MaxReportSize

type options struct {
	targetAuth, targetCA, proxyCA, clientCertDir string
	// sourceAuth and sourceCA are optional: a missing file means anonymous
	// pulls and no extra source root.
	sourceAuth, sourceCA string
	// azureToken is the projected ServiceAccount token for Azure workload identity.
	azureToken string
	// awsToken is the projected ServiceAccount token for AWS IRSA.
	awsToken string
	// awsSTS and awsECR replace the STS and ECR API endpoints that the
	// region gives. Only tests set them.
	awsSTS, awsECR string
	// gcpToken is the projected ServiceAccount token for Google Cloud
	// Workload Identity Federation.
	gcpToken string
	// gcpSTS and gcpIAM replace https://sts.googleapis.com and
	// https://iamcredentials.googleapis.com. Only tests set them.
	gcpSTS, gcpIAM string
	// allowLoopback lets loopback addresses pass the source checks. Only
	// tests set it, for in-process registries on 127.0.0.1; every other
	// internal address is still refused.
	allowLoopback bool
	// lookup resolves host names. Tests replace it.
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	// window bounds lookup and connection retries at the start of a run.
	window *registry.Window
}

// transientError marks an error that may pass on the next run.
type transientError struct{ error }

func (e transientError) Unwrap() error { return e.error }

// Run runs one sync and returns one of the syncspec exit codes.
func Run(ctx context.Context, args []string, stdout io.Writer, termPath string) int {
	o := options{
		targetAuth: syncspec.TargetAuthFile, targetCA: syncspec.TargetCAFile,
		proxyCA: syncspec.ProxyCAFile, clientCertDir: syncspec.ClientCertDir,
		sourceAuth: syncspec.SourceAuthFile, sourceCA: syncspec.SourceCAFile,
		azureToken: syncspec.AzureTokenFile, awsToken: syncspec.AWSTokenFile, gcpToken: syncspec.GCPTokenFile,
		lookup: net.DefaultResolver.LookupIPAddr,
	}
	return run(ctx, args, stdout, termPath, o, os.Getenv)
}

func run(ctx context.Context, args []string, stdout io.Writer, termPath string, o options, getenv func(string) string) (code int) {
	defer func() {
		// The panic value may hold anything, so it is not reported.
		if recover() != nil {
			writeTermination(stdout, termPath, report{Errors: []string{"internal error"}})
			code = syncspec.ExitSyncFailed
		}
	}()
	spec, req, err := setup(ctx, args, o, getenv)
	if err != nil {
		writeTermination(stdout, termPath, report{Errors: []string{err.Error()}})
		if errors.As(err, new(transientError)) {
			return syncspec.ExitSyncFailed
		}
		return syncspec.ExitConfig
	}
	res, err := sync.Run(ctx, req)
	audit(stdout, spec, res)
	r := summarize(res)
	code = syncspec.ExitOK
	if err != nil {
		code = syncspec.ExitSyncFailed
		// Per-tag errors are already listed; keep run-level ones such as a
		// failed listing or a cancelled context.
		if len(res.Errors) == 0 || ctx.Err() != nil {
			r.Errors = append(r.Errors, err.Error())
		}
	}
	writeTermination(stdout, termPath, r)
	return code
}

func setup(ctx context.Context, args []string, p options, getenv func(string) string) (syncspec.Spec, sync.Request, error) {
	fl := flag.NewFlagSet("sync", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	specPath := fl.String("spec", syncspec.SpecFile, "path to the sync spec")
	if err := fl.Parse(args); err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	if fl.NArg() > 0 {
		return syncspec.Spec{}, sync.Request{}, fmt.Errorf("unexpected arguments %q", fl.Args())
	}
	f, err := os.Open(*specPath)
	if err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	defer func() { _ = f.Close() }()
	spec, err := syncspec.Decode(f)
	if err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	p.window = registry.NewWindow()
	p.lookup = cachedLookup(p.lookup, p.window)
	if err := checkSource(ctx, spec, p, getenv("HTTPS_PROXY") != ""); err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	srcT, dstT, err := transports(p, spec.DeniedPrefixes, getenv)
	if err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	var auth authn.Authenticator
	if spec.TargetAuth != "" {
		auth, err = cloudAuth(ctx, spec.TargetAuth, spec, p, dstT, spec.TargetRepo.Registry, "target")
	} else {
		auth, err = dockerAuth(p.targetAuth, spec.TargetRepo.RegistryStr(), "target")
	}
	if err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	srcAuth := authn.Anonymous
	if spec.SourceAuth != "" {
		srcAuth, err = cloudAuth(ctx, spec.SourceAuth, spec, p, srcT, spec.SourceRepo.Registry, "source")
	} else if _, serr := os.Stat(p.sourceAuth); !errors.Is(serr, fs.ErrNotExist) {
		srcAuth, err = dockerAuth(p.sourceAuth, spec.SourceRepo.RegistryStr(), "source")
	}
	if err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	return spec, sync.Request{
		Source:            spec.SourceRepo,
		Target:            spec.TargetRepo,
		Policy:            spec.Tags,
		RequiredPlatforms: spec.RequiredPlatforms,
		OnTagMutation:     spec.OnTagMutation,
		MaxTags:           spec.MaxTags,
		MaxArtifactSize:   spec.MaxArtifactSize,
		SourceOpts:        []remote.Option{remote.WithTransport(srcT), remote.WithAuth(srcAuth)},
		TargetOpts:        []remote.Option{remote.WithTransport(dstT), remote.WithAuth(auth)},
	}, nil
}

// dockerAuth reads the credentials for host from a dockerconfigjson file;
// what names the registry role in errors. Only static auths are read:
// credsStore and credHelpers would run binaries. Docker Hub names match
// each other. Errors never quote the file content.
func dockerAuth(path, host, what string) (authn.Authenticator, error) {
	b, err := os.ReadFile(path) //nolint:gosec // fixed in-pod path
	if err != nil {
		return nil, fmt.Errorf("%s credentials: %w", what, err)
	}
	var cfg struct {
		Auths map[string]struct {
			Auth, Username, Password, IdentityToken, RegistryToken string
		} `json:"auths"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil, fmt.Errorf("%s credentials: not a valid dockerconfigjson", what)
	}
	// Prefer the key that is exactly the host, else the first matching key
	// in sorted order, so the choice never depends on map order.
	keys := slices.Sorted(maps.Keys(cfg.Auths))
	same := func(a, b string) bool { return syncspec.CanonicalRegistry(a) == syncspec.CanonicalRegistry(b) }
	i := slices.IndexFunc(keys, func(k string) bool { return same(k, host) })
	if i < 0 {
		i = slices.IndexFunc(keys, func(k string) bool { return same(syncspec.AuthKeyHost(k), host) })
	}
	if i >= 0 {
		a := cfg.Auths[keys[i]]
		c := authn.AuthConfig{
			Username: a.Username, Password: a.Password,
			IdentityToken: a.IdentityToken, RegistryToken: a.RegistryToken,
		}
		if a.Auth != "" {
			dec, err := base64.StdEncoding.DecodeString(a.Auth)
			user, pass, ok := strings.Cut(string(dec), ":")
			if err != nil || !ok {
				return nil, fmt.Errorf("%s credentials: invalid auth for %s", what, host)
			}
			c.Username, c.Password = user, pass
		}
		return authn.FromConfig(c), nil
	}
	return nil, fmt.Errorf("%s credentials: no entry for %s", what, host)
}

// transports builds the source and target transports. The source trusts
// the proxy CA and the source CA; the target trusts the proxy CA and its
// own CA and presents the client certificate.
func transports(p options, denied []netip.Prefix, getenv func(string) string) (src, dst http.RoundTripper, err error) {
	proxyCA, err := readOptional(p.proxyCA)
	if err != nil {
		return nil, nil, err
	}
	targetCA, err := readOptional(p.targetCA)
	if err != nil {
		return nil, nil, err
	}
	// Only the proxy from the spec applies, never a lowercase or HTTP_PROXY
	// variable that the image or node happens to set.
	o := registry.Options{CAPEM: proxyCA, NoEnvProxy: true, Window: p.window}
	user, pass := getenv(syncspec.ProxyUserEnv), getenv(syncspec.ProxyPasswordEnv)
	if proxy := getenv("HTTPS_PROXY"); proxy != "" {
		// Never quote the URL: it may hold credentials.
		if o.ProxyURL, err = url.Parse(proxy); err != nil {
			return nil, nil, errors.New("HTTPS_PROXY is not a valid URL")
		}
		if noProxy := getenv("NO_PROXY"); noProxy != "" {
			o.NoProxy = []string{noProxy}
		}
		o.ProxyUser, o.ProxyPassword = user, pass
	} else if user != "" || pass != "" {
		return nil, nil, errors.New("proxy credentials are set but HTTPS_PROXY is not")
	}
	sourceCA, err := readOptional(p.sourceCA)
	if err != nil {
		return nil, nil, err
	}
	so := o
	if len(sourceCA) > 0 {
		so.CAPEM = append(append(slices.Clone(o.CAPEM), '\n'), sourceCA...)
	}
	so.CheckHost = func(ctx context.Context, host string, proxied bool) error {
		return p.checkHost(ctx, host, proxied, denied)
	}
	so.CheckDial = func(a netip.Addr) error { return p.checkAddrs([]netip.Addr{a}, denied) }
	if src, err = registry.NewTransport(so); err != nil {
		return nil, nil, fmt.Errorf("source transport: %w", err)
	}

	if len(targetCA) > 0 {
		o.CAPEM = append(append(o.CAPEM, '\n'), targetCA...)
	}
	cert, err := readOptional(filepath.Join(p.clientCertDir, "tls.crt"))
	if err != nil {
		return nil, nil, err
	}
	key, err := readOptional(filepath.Join(p.clientCertDir, "tls.key"))
	if err != nil {
		return nil, nil, err
	}
	if cert != nil || key != nil {
		c, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, nil, fmt.Errorf("client certificate: %w", err)
		}
		o.ClientCert = &c
	}
	if dst, err = registry.NewTransport(o); err != nil {
		return nil, nil, fmt.Errorf("target transport: %w", err)
	}
	return src, dst, nil
}

// checkSource refuses a source registry that the target does not allow or
// that is an internal address (threat model T6, T16). It runs before any
// registry call; the source transport repeats the address check on every
// request and connection.
func checkSource(ctx context.Context, spec syncspec.Spec, o options, proxied bool) error {
	host := spec.SourceRepo.RegistryStr()
	if !syncspec.AllowedSource(host, spec.AllowedSources) {
		return fmt.Errorf("source: registry %s is not in allowedSources", host)
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	if err := o.checkHost(ctx, strings.Trim(name, "[]"), proxied, spec.DeniedPrefixes); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	return nil
}

// checkHost refuses a host name or literal address that resolves to an
// internal address. A proxy resolves names itself and its ACL is the
// control there, so a name the Job cannot resolve passes when the request
// is proxied. Without a proxy a lookup error is transient.
func (o options) checkHost(ctx context.Context, name string, proxied bool, denied []netip.Prefix) error {
	if a, err := netip.ParseAddr(name); err == nil {
		return o.checkAddrs([]netip.Addr{a}, denied)
	}
	ips, err := o.lookup(ctx, name)
	switch {
	case err != nil && proxied:
		return nil
	case err != nil:
		return transientError{fmt.Errorf("resolve %s: %w", name, err)}
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.IP); ok {
			addrs = append(addrs, a)
		}
	}
	if err := o.checkAddrs(addrs, denied); err != nil {
		return fmt.Errorf("%s %w", name, err)
	}
	return nil
}

// cachedLookup resolves each host once per run, so every request to a host
// is checked against the same answer. During the startup window a
// temporary error, such as a resolver rejected until the pod's
// NetworkPolicy is programmed, is retried and not cached, so the next
// request tries again. Behind a proxy a lookup error passes, so a cached
// race failure would skip the check for the whole run.
func cachedLookup(lookup func(context.Context, string) ([]net.IPAddr, error), w *registry.Window) func(context.Context, string) ([]net.IPAddr, error) {
	type answer struct {
		ips []net.IPAddr
		err error
	}
	var mu stdsync.Mutex
	cache := map[string]answer{}
	return func(ctx context.Context, host string) ([]net.IPAddr, error) {
		var a answer
		err := registry.Retry(ctx, w, registry.TemporaryDNS, func() error {
			mu.Lock()
			defer mu.Unlock()
			var ok bool
			if a, ok = cache[host]; !ok {
				a.ips, a.err = lookup(ctx, host)
				if !registry.TemporaryDNS(a.err) || !w.Open() {
					cache[host] = a
				}
			}
			return a.err
		})
		return a.ips, err
	}
}

// checkAddrs refuses an address that syncspec.CheckAddr refuses. Only
// tests set allowLoopback.
func (o options) checkAddrs(addrs []netip.Addr, denied []netip.Prefix) error {
	for _, a := range addrs {
		if o.allowLoopback && a.Unmap().IsLoopback() {
			continue
		}
		if err := syncspec.CheckAddr(a, denied); err != nil {
			return err
		}
	}
	return nil
}

// readOptional returns nil for a missing file and an error for one that
// exists but cannot be read.
func readOptional(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // fixed in-pod paths
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

type auditLine struct {
	TS        string `json:"ts"`
	Mirror    string `json:"mirror"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Action    string `json:"action"`
	Referrers int    `json:"referrers"`
	// UpstreamDigest is set for a mutation-ignored line.
	UpstreamDigest string `json:"upstreamDigest,omitempty"`
	Error          string `json:"error,omitempty"`
}

// audit writes one JSON line per selected tag, newest first.
func audit(w io.Writer, spec syncspec.Spec, res sync.Result) {
	type entry struct {
		a      sync.Artifact
		action string
	}
	byTag := map[string]entry{}
	add := func(as []sync.Artifact, action string) {
		for _, a := range as {
			byTag[a.Tag] = entry{a, action}
		}
	}
	// Later lists win: an overwritten tag is in Copied and Mutated.
	add(res.Skipped, "skipped")
	add(res.Copied, "copied")
	add(res.Mutated, "mutated")
	add(res.Failed, "failed")
	errs := map[string]string{}
	for _, e := range res.Errors {
		if tag, msg, ok := strings.Cut(e, ": "); ok {
			errs[tag] = msg
		}
	}
	enc := json.NewEncoder(w)
	for _, tag := range res.Selected {
		e, ok := byTag[tag]
		if !ok {
			continue
		}
		l := auditLine{
			TS:        e.a.Finished.UTC().Format(time.RFC3339Nano),
			Mirror:    spec.Mirror.Namespace + "/" + spec.Mirror.Name,
			Source:    spec.SourceRepo.String() + ":" + tag,
			Target:    spec.TargetRepo.String() + ":" + tag,
			Action:    e.action,
			Referrers: e.a.Referrers,
			Error:     errs[tag],
		}
		switch {
		case e.a.UpstreamDigest != "":
			// The target keeps its digest; the source moved on.
			l.Action, l.UpstreamDigest = "mutation-ignored", e.a.UpstreamDigest
			l.Source += "@" + e.a.UpstreamDigest
			l.Target += "@" + e.a.Digest
		case e.a.Digest != "":
			l.Source += "@" + e.a.Digest
		}
		_ = enc.Encode(l)
	}
}

type (
	syncedTag = syncspec.SyncedTag
	report    = syncspec.Report
)

// summarize lists the tags on the target after the run, newest first.
func summarize(res sync.Result) report {
	digests := map[string]string{}
	for _, a := range append(res.Skipped, res.Copied...) {
		digests[a.Tag] = a.Digest
	}
	r := report{
		Copied: len(res.Copied), Skipped: len(res.Skipped), Mutated: len(res.Mutated), Failed: len(res.Failed),
		Synced: []syncedTag{},
		Errors: res.Errors,
	}
	for _, tag := range res.Selected {
		if d, ok := digests[tag]; ok {
			r.Synced = append(r.Synced, syncedTag{Tag: tag, Digest: d})
		}
	}
	return r
}

// Errors kept first when the report must be truncated, and their cap.
const (
	keptErrors   = 3
	keptErrorLen = 200
)

// encode marshals r within maxTermination bytes. When r does not fit, it
// keeps the first errors cut to keptErrorLen bytes, then as many synced
// tags as fit, then as many further errors as fit, and flags what it cut.
func encode(r report) []byte {
	r.V = syncspec.ReportVersion
	if r.Synced == nil {
		r.Synced = []syncedTag{}
	}
	marshal := func(r report) []byte {
		b, _ := json.Marshal(r)
		return b
	}
	fits := func(r report) bool { return len(marshal(r)) <= maxTermination }
	if fits(r) {
		return marshal(r)
	}
	errs, synced := r.Errors, r.Synced
	head := make([]string, 0, keptErrors)
	for _, e := range errs[:min(keptErrors, len(errs))] {
		c := cut(e, keptErrorLen)
		r.ErrorsTruncated = r.ErrorsTruncated || c != e
		head = append(head, c)
	}
	rest := errs[len(head):]
	withRest := func(k int) []string { return append(slices.Clip(head), rest[:k]...) }

	r.Errors = head
	if !fits(r) {
		r.Truncated = true
		r.Synced = synced[:largest(len(synced), func(k int) bool { r.Synced = synced[:k]; return fits(r) })]
	}
	n := largest(len(rest), func(k int) bool { r.Errors = withRest(k); return fits(r) })
	r.Errors = withRest(n)
	r.ErrorsTruncated = r.ErrorsTruncated || n < len(rest)
	return marshal(r)
}

// cut shortens s to at most n bytes without splitting a rune.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// largest returns the largest k in [0, n] for which ok(k) holds, assuming
// ok is monotonic.
func largest(n int, ok func(int) bool) int {
	lo, hi := 0, n
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if ok(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// writeTermination writes the report in a single write. Without a path,
// for example when run by hand, it does nothing.
func writeTermination(stdout io.Writer, path string, r report) {
	if path == "" {
		return
	}
	if err := os.WriteFile(path, encode(r), 0o600); err != nil {
		_ = json.NewEncoder(stdout).Encode(map[string]string{"ts": time.Now().UTC().Format(time.RFC3339), "error": err.Error()})
	}
}
