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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/sync"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

// TerminationLogPath is where Kubernetes reads the termination message.
const TerminationLogPath = "/dev/termination-log"

// maxTermination is the Kubernetes limit for a termination message.
const maxTermination = 4096

// Exit codes.
const (
	exitOK     = 0
	exitFailed = 1
	exitConfig = 2
)

type paths struct {
	targetAuth, targetCA, proxyCA, clientCertDir string
}

// Run runs one sync and returns the exit code: 0 when every selected tag is
// on the target, 1 when a tag failed or a mutation was refused, 2 on a spec
// or configuration error.
func Run(ctx context.Context, args []string, stdout io.Writer, termPath string) int {
	p := paths{syncspec.TargetAuthFile, syncspec.TargetCAFile, syncspec.ProxyCAFile, syncspec.ClientCertDir}
	return run(ctx, args, stdout, termPath, p, os.Getenv)
}

func run(ctx context.Context, args []string, stdout io.Writer, termPath string, p paths, getenv func(string) string) int {
	spec, req, err := setup(args, p, getenv)
	if err != nil {
		writeTermination(stdout, termPath, report{Errors: []string{err.Error()}})
		return exitConfig
	}
	res, err := sync.Run(ctx, req)
	audit(stdout, spec, res)
	r := summarize(res)
	code := exitOK
	if err != nil {
		code = exitFailed
		// Per-tag errors are already listed; keep run-level ones such as a
		// failed listing or a cancelled context.
		if len(res.Errors) == 0 || ctx.Err() != nil {
			r.Errors = append(r.Errors, err.Error())
		}
	}
	writeTermination(stdout, termPath, r)
	return code
}

func setup(args []string, p paths, getenv func(string) string) (syncspec.Spec, sync.Request, error) {
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
	auth, err := targetAuth(p.targetAuth, spec.TargetRepo.RegistryStr())
	if err != nil {
		return syncspec.Spec{}, sync.Request{}, err
	}
	srcT, dstT, err := transports(p, getenv)
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
		// Phase 1 pulls anonymously; per-source credentials come later.
		SourceOpts: []remote.Option{remote.WithTransport(srcT), remote.WithAuth(authn.Anonymous)},
		TargetOpts: []remote.Option{remote.WithTransport(dstT), remote.WithAuth(auth)},
	}, nil
}

// targetAuth reads the credentials for host from a dockerconfigjson file.
// Only static auths are read: credsStore and credHelpers would run binaries.
// Errors never quote the file content.
func targetAuth(path, host string) (authn.Authenticator, error) {
	b, err := os.ReadFile(path) //nolint:gosec // fixed in-pod path
	if err != nil {
		return nil, fmt.Errorf("target credentials: %w", err)
	}
	var cfg struct {
		Auths map[string]struct {
			Auth, Username, Password, IdentityToken, RegistryToken string
		} `json:"auths"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil, errors.New("target credentials: not a valid dockerconfigjson")
	}
	for key, a := range cfg.Auths {
		if registryHost(key) != host {
			continue
		}
		c := authn.AuthConfig{
			Username: a.Username, Password: a.Password,
			IdentityToken: a.IdentityToken, RegistryToken: a.RegistryToken,
		}
		if a.Auth != "" {
			dec, err := base64.StdEncoding.DecodeString(a.Auth)
			user, pass, ok := strings.Cut(string(dec), ":")
			if err != nil || !ok {
				return nil, fmt.Errorf("target credentials: invalid auth for %s", host)
			}
			c.Username, c.Password = user, pass
		}
		return authn.FromConfig(c), nil
	}
	return nil, fmt.Errorf("target credentials: no entry for %s", host)
}

// registryHost turns a docker config key such as https://host/v1/ into host.
func registryHost(key string) string {
	key = strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")
	host, _, _ := strings.Cut(key, "/")
	return host
}

// transports builds the source and target transports. The source trusts
// only the proxy CA; the target also trusts its own CA and presents the
// client certificate.
func transports(p paths, getenv func(string) string) (src, dst http.RoundTripper, err error) {
	proxyCA, err := readOptional(p.proxyCA)
	if err != nil {
		return nil, nil, err
	}
	targetCA, err := readOptional(p.targetCA)
	if err != nil {
		return nil, nil, err
	}
	o := registry.Options{CAPEM: proxyCA}
	user, pass := getenv(syncspec.ProxyUserEnv), getenv(syncspec.ProxyPasswordEnv)
	if proxy := getenv("HTTPS_PROXY"); proxy != "" {
		// Never quote the URL: it may hold credentials.
		if o.ProxyURL, err = url.Parse(proxy); err != nil {
			return nil, nil, errors.New("HTTPS_PROXY is not a valid URL")
		}
		if noProxy := getenv("NO_PROXY"); noProxy != "" {
			o.NoProxy = strings.Split(noProxy, ",")
		}
		o.ProxyUser, o.ProxyPassword = user, pass
	} else if user != "" || pass != "" {
		return nil, nil, errors.New("proxy credentials are set but HTTPS_PROXY is not")
	}
	if src, err = registry.NewTransport(o); err != nil {
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
	Error     string `json:"error,omitempty"`
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
		src := spec.SourceRepo.String() + ":" + tag
		if e.a.Digest != "" {
			src += "@" + e.a.Digest
		}
		_ = enc.Encode(auditLine{
			TS:        time.Now().UTC().Format(time.RFC3339),
			Mirror:    spec.Mirror.Namespace + "/" + spec.Mirror.Name,
			Source:    src,
			Target:    spec.TargetRepo.String() + ":" + tag,
			Action:    e.action,
			Referrers: e.a.Referrers,
			Error:     errs[tag],
		})
	}
}

type syncedTag struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

// report is the termination message the controller reads.
type report struct {
	V               int         `json:"v"`
	Copied          int         `json:"copied"`
	Skipped         int         `json:"skipped"`
	Mutated         int         `json:"mutated"`
	Failed          int         `json:"failed"`
	Synced          []syncedTag `json:"synced"`
	Errors          []string    `json:"errors,omitempty"`
	ErrorsTruncated bool        `json:"errorsTruncated,omitempty"`
	Truncated       bool        `json:"truncated,omitempty"`
}

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
			r.Synced = append(r.Synced, syncedTag{tag, d})
		}
	}
	return r
}

// encode marshals r within maxTermination bytes. It drops errors from the
// end first, then synced tags from the end, and flags what it dropped.
func encode(r report) []byte {
	r.V = 1
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
	r.ErrorsTruncated = len(errs) > 0
	r.Errors = errs[:largest(len(errs), func(k int) bool { r.Errors = errs[:k]; return fits(r) })]
	if !fits(r) {
		r.Truncated = true
		r.Synced = synced[:largest(len(synced), func(k int) bool { r.Synced = synced[:k]; return fits(r) })]
	}
	return marshal(r)
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
