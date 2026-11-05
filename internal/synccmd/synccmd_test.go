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

package synccmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	twregistry "github.com/r-gawronski/tagwarden/internal/registry"
	"github.com/r-gawronski/tagwarden/internal/sync"
	"github.com/r-gawronski/tagwarden/internal/syncspec"
	twtags "github.com/r-gawronski/tagwarden/internal/tags"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	v110          = "v1.1.0"
	user          = "pusher"
	password      = "s3cret-push-pass"
	sourcePass    = "s3cret-source-pull"
	proxyPassword = "s3cret-proxy-pass"
	dnsTimeout    = "timeout"
	dnsNotFound   = "no such host"
)

func golden(t *testing.T, file string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", file)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch:\ngot  %s\nwant %s", file, got, want)
	}
}

func TestEncodeReport(t *testing.T) {
	r := report{
		Copied: 1, Skipped: 1, Mutated: 1, Failed: 1,
		Synced: []syncedTag{{Tag: v110, Digest: "sha256:" + strings.Repeat("a", 64)}, {Tag: "v1.0.0", Digest: "sha256:" + strings.Repeat("b", 64)}},
		Errors: []string{"v0.9.0: resolve source tag: not found"},
	}
	golden(t, "report.golden", encode(r))
}

func TestEncodeReportTruncates(t *testing.T) {
	var r report
	for i := range 200 {
		r.Synced = append(r.Synced, syncedTag{Tag: fmt.Sprintf("v1.0.%d-%s", 200-i, strings.Repeat("x", 100)), Digest: "sha256:" + strings.Repeat("c", 64)})
	}
	for i := range 10 {
		r.Errors = append(r.Errors, fmt.Sprintf("v0.%d.0: %s", i, strings.Repeat("e", 200)))
	}
	r.Copied, r.Failed = 200, 10

	t.Run("errors and synced", func(t *testing.T) {
		b := encode(r)
		var got report
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		// The first errors are kept, cut short, before any synced tag.
		if len(b) > maxTermination || !got.Truncated || !got.ErrorsTruncated || len(got.Errors) != 3 ||
			len(got.Errors[0]) != 200 || len(got.Synced) == 0 {
			t.Fatalf("%d bytes: %s", len(b), b)
		}
		golden(t, "report_truncated.golden", b)
	})
	t.Run("errors only", func(t *testing.T) {
		r := r
		r.Synced = r.Synced[:10]
		b := encode(r)
		var got report
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if len(b) > maxTermination || got.Truncated || !got.ErrorsTruncated || len(got.Synced) != 10 ||
			len(got.Errors) <= 3 || len(got.Errors) == 10 || len(got.Errors[0]) != 200 || len(got.Errors[3]) <= 200 {
			t.Fatalf("%d bytes: %s", len(b), b)
		}
	})
}

func newRegistry(t *testing.T, auth bool) name.Repository {
	t.Helper()
	if auth {
		return newRegistryPass(t, password)
	}
	return newRegistryPass(t, "")
}

// newRegistryPass requires basic auth with pass; an empty pass means none.
func newRegistryPass(t *testing.T, pass string) name.Repository {
	t.Helper()
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); pass != "" && (!ok || u != user || p != pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://")+"/team/app", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

type env struct {
	dir    string
	opts   options
	vars   map[string]string
	spec   string
	target string
}

// newEnv writes a dockerconfigjson for target with pass and a spec.
func newEnv(t *testing.T, source, target name.Repository, pass string) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{
		dir: dir,
		opts: options{
			targetAuth:    filepath.Join(dir, "auth.json"),
			targetCA:      filepath.Join(dir, "missing", "ca.crt"),
			proxyCA:       filepath.Join(dir, "missing", "proxy.crt"),
			sourceAuth:    filepath.Join(dir, "missing", "source.json"),
			sourceCA:      filepath.Join(dir, "missing", "source-ca.crt"),
			clientCertDir: filepath.Join(dir, "missing"),
			// The in-process registries listen on 127.0.0.1.
			allowLoopback: true,
			lookup:        net.DefaultResolver.LookupIPAddr,
		},
		vars:   map[string]string{},
		spec:   filepath.Join(dir, "spec.json"),
		target: target.String(),
	}
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	cfg := fmt.Sprintf(`{"auths":{"https://%s/v1/":{"auth":%q}}}`, target.RegistryStr(), auth)
	e.write(t, e.opts.targetAuth, cfg)
	e.writeSpec(t, source.String(), `"allowedSources":[`+strconv.Quote(source.RegistryStr())+`]`)
	return e
}

// writeSpec writes a spec for source; extra holds the source check fields.
func (e *env) writeSpec(t *testing.T, source, extra string) {
	t.Helper()
	e.write(t, e.spec, fmt.Sprintf(`{"mirror":{"namespace":"team-a","name":"app"},"source":%q,"target":%q,
		"tags":{"keepLatest":2},"onTagMutation":"Fail",%s}`, source, e.target, extra))
}

func (e *env) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
}

// run returns the exit code, stdout and the termination message.
func (e *env) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out bytes.Buffer
	term := filepath.Join(e.dir, "termination-log")
	code := run(context.Background(), append([]string{"--spec", e.spec}, args...), &out, term, e.opts, func(k string) string { return e.vars[k] })
	msg, err := os.ReadFile(term) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) > maxTermination {
		t.Fatalf("termination message has %d bytes", len(msg))
	}
	return code, out.String(), string(msg)
}

func pushImages(t *testing.T, repo name.Repository, tags ...string) {
	t.Helper()
	for _, tag := range tags {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Write(repo.Tag(tag), img); err != nil {
			t.Fatal(err)
		}
	}
}

func auditLines(t *testing.T, out string) []auditLine {
	t.Helper()
	var lines []auditLine
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		d := json.NewDecoder(strings.NewReader(s.Text()))
		d.DisallowUnknownFields()
		var l auditLine
		if err := d.Decode(&l); err != nil {
			t.Fatalf("audit line %q: %v", s.Text(), err)
		}
		lines = append(lines, l)
	}
	return lines
}

func assertNoSecrets(t *testing.T, outputs ...string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	srcAuth := base64.StdEncoding.EncodeToString([]byte(user + ":" + sourcePass))
	for _, o := range outputs {
		for _, s := range []string{password, proxyPassword, auth, sourcePass, srcAuth} {
			if strings.Contains(o, s) {
				t.Fatalf("secret in output: %s", o)
			}
		}
	}
}

func TestRunSyncs(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, true)
	pushImages(t, src, "v1.0.0", v110, "v1.2.0")
	e := newEnv(t, src, dst, password)

	code, out, msg := e.run(t)
	if code != syncspec.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	var r report
	if err := json.Unmarshal([]byte(msg), &r); err != nil {
		t.Fatal(err)
	}
	if r.V != 1 || r.Copied != 2 || r.Failed != 0 || len(r.Synced) != 2 ||
		r.Synced[0].Tag != "v1.2.0" || r.Synced[1].Tag != v110 || len(r.Errors) != 0 {
		t.Fatalf("report %s", msg)
	}
	lines := auditLines(t, out)
	if len(lines) != 2 {
		t.Fatalf("audit %s", out)
	}
	for i, l := range lines {
		tag := r.Synced[i].Tag
		if l.TS == "" || l.Mirror != "team-a/app" || l.Action != actionCopied || l.Error != "" ||
			l.Source != src.String()+":"+tag+"@"+r.Synced[i].Digest || l.Target != dst.String()+":"+tag {
			t.Fatalf("audit line %+v", l)
		}
	}
	ts, err := remote.List(dst, remote.WithAuth(&authn.Basic{Username: user, Password: password}))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ts)
	if !slices.Equal(ts, []string{v110, "v1.2.0"}) {
		t.Fatalf("target tags %v", ts)
	}

	code, out, msg = e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"skipped":2`) || strings.Count(out, `"action":"skipped"`) != 2 {
		t.Fatalf("second run exit %d: %s\n%s", code, msg, out)
	}
	assertNoSecrets(t, out, msg)
}

func TestRunWrongPassword(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, true)
	pushImages(t, src, "v1.0.0", v110)
	e := newEnv(t, src, dst, "wrong-"+password)
	e.vars["HTTPS_PROXY"] = "http://proxy.example.internal:3128"
	e.vars[syncspec.ProxyUserEnv] = "proxy-user"
	e.vars[syncspec.ProxyPasswordEnv] = proxyPassword

	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, `"failed":2`) || strings.Count(out, `"action":"failed"`) != 2 {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	assertNoSecrets(t, out, msg) // password is a substring of the wrong one
}

func TestRunAuditsArtifactTooLarge(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, true)
	pushImages(t, src, "v1.0.0", v110)
	e := newEnv(t, src, dst, password)
	e.writeSpec(t, src.String(), `"allowedSources":[`+strconv.Quote(src.RegistryStr())+`],"maxArtifactSize":10`)

	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, `"failed":2`) {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	for _, l := range auditLines(t, out) {
		if l.Action != "failed" || !strings.HasPrefix(l.Error, "artifact too large: ") || !strings.HasSuffix(l.Error, " > 10") {
			t.Fatalf("audit line %+v", l)
		}
	}
}

// Behind a proxy any lookup failure passes: the proxy resolves names and
// its ACL is the control. A temporary error is retried on every check
// while the startup window is open.
func TestRunProxiedLookupFailure(t *testing.T) {
	stubWait(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(proxy.Close)
	src, err := name.NewRepository(exampleTargetRepo)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, src, newRegistry(t, true), password)
	e.vars["HTTPS_PROXY"] = proxy.URL
	lookups := map[string]int{}
	e.opts.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups[host]++
		return nil, &net.DNSError{Err: dnsTimeout, Name: host, IsTimeout: true}
	}
	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, "list source tags") {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	if n := lookups["registry.example.internal"]; n == 0 || n%(len(twregistry.Backoff)+1) != 0 {
		t.Fatalf("lookups %v, want full retry schedules", lookups)
	}
}

// The proxy gets the credentials; they never reach stdout or the
// termination message.
func TestRunProxyCredentials(t *testing.T) {
	got := make(chan string, 10)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(proxy.Close)
	// Go never proxies loopback, so the source must have a real host name.
	src, err := name.NewRepository(exampleTargetRepo)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, src, newRegistry(t, true), password)
	e.vars["HTTPS_PROXY"] = proxy.URL
	// The Job cannot resolve upstream names; the proxy does.
	e.opts.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: dnsNotFound, Name: host, IsNotFound: true}
	}
	e.vars[syncspec.ProxyUserEnv] = "proxy-user"
	e.vars[syncspec.ProxyPasswordEnv] = proxyPassword

	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, "list source tags") {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:"+proxyPassword))
	if h := <-got; h != want {
		t.Fatalf("Proxy-Authorization %q", h)
	}
	assertNoSecrets(t, out, msg)
}

func TestRunConfigErrors(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, true)
	cases := map[string]func(e *env){
		"bad spec":       func(e *env) { e.write(t, e.spec, `{"source":"x"}`) },
		"missing spec":   func(e *env) { e.spec = filepath.Join(e.dir, "nope.json") },
		"missing auth":   func(e *env) { e.opts.targetAuth = filepath.Join(e.dir, "nope") },
		"auth elsewhere": func(e *env) { e.write(t, e.opts.targetAuth, `{"auths":{"other.example.internal":{"auth":"eDp5"}}}`) },
		"bad auth":       func(e *env) { e.write(t, e.opts.targetAuth, `{"auths":`) },
		"unreadable CA":  func(e *env) { e.opts.targetCA = e.dir },
		"bad source auth": func(e *env) {
			e.opts.sourceAuth = filepath.Join(e.dir, "source.json")
			e.write(t, e.opts.sourceAuth, `{"auths":`)
		},
		"source auth elsewhere": func(e *env) {
			e.opts.sourceAuth = filepath.Join(e.dir, "source.json")
			e.write(t, e.opts.sourceAuth, `{"auths":{"other.example.internal":{"auth":"eDp5"}}}`)
		},
		"unreadable source auth": func(e *env) { e.opts.sourceAuth = e.dir },
		"empty source CA":        func(e *env) { e.opts.sourceCA = e.spec },
		"empty CA":               func(e *env) { e.opts.proxyCA = e.spec },
		"key without cert": func(e *env) {
			e.opts.clientCertDir = e.dir
			e.write(t, filepath.Join(e.dir, "tls.key"), "x")
		},
		"proxy password without proxy": func(e *env) { e.vars[syncspec.ProxyPasswordEnv] = proxyPassword },
		"bad proxy url": func(e *env) {
			e.vars["HTTPS_PROXY"] = "http://u:" + proxyPassword + "@[::1"
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			e := newEnv(t, src, dst, password)
			mutate(e)
			code, out, msg := e.run(t)
			var r report
			if err := json.Unmarshal([]byte(msg), &r); err != nil {
				t.Fatal(err)
			}
			if code != syncspec.ExitConfig || len(r.Errors) != 1 || out != "" {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			t.Log(r.Errors[0])
			assertNoSecrets(t, out, msg)
		})
	}
}

func TestRunRefusesSources(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	local := strings.TrimPrefix(srv.URL, "http://")
	cases := []struct{ source, allowed, denied, want string }{
		{local + "/team/app", `"` + local + `"`, "", "internal"}, //nolint:goconst // readable fixtures
		{"169.254.169.254/team/app", `"169.254.169.254"`, "", "internal"},
		{"[::1]:5000/team/app", `"[::1]:5000"`, "", "internal"},
		{"localhost:5000/team/app", `"localhost:5000"`, "", "internal"},
		{"10.96.0.10/team/app", `"10.96.0.10"`, `"10.96.0.0/12"`, "denied"},
		{exampleTargetRepo, `"other.example.internal"`, "", "not in allowedSources"},
		{"registry.example.internal:5000/team/app", `"registry.example.internal"`, "", "not in allowedSources"},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			e := newEnv(t, newRegistry(t, false), newRegistry(t, true), password)
			e.opts.allowLoopback = false
			e.writeSpec(t, tc.source, `"allowedSources":[`+tc.allowed+`],"deniedCIDRs":[`+tc.denied+`]`)
			code, out, msg := e.run(t)
			if code != syncspec.ExitConfig || !strings.Contains(msg, tc.want) || out != "" {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("refused source got %d requests", n)
	}
}

func TestCheckAddrs(t *testing.T) {
	denied := []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}
	cases := map[string]bool{
		"203.0.113.10":        true,
		"2001:db8::1":         true,
		"10.0.0.1":            true,
		"10.96.0.10":          false,
		"127.0.0.1":           false,
		"::1":                 false,
		"::ffff:127.0.0.1":    false,
		"169.254.10.1":        false,
		"169.254.169.254":     false,
		"fe80::1":             false,
		"fd00:ec2::254":       false,
		"0.0.0.0":             false,
		"::":                  false,
		"::ffff:169.254.0.10": false,
		"100.100.100.200":     false,
		"0.1.2.3":             false,
		"64:ff9b::7f00:1":     false,
		"64:ff9b::a9fe:a9fe":  false,
		"64:ff9b::cb00:710a":  true,
	}
	var o options
	for a, ok := range cases {
		err := o.checkAddrs([]netip.Addr{netip.MustParseAddr(a)}, denied)
		if (err == nil) != ok {
			t.Errorf("%s: err %v, want ok=%v", a, err, ok)
		}
	}
	// Any internal address refuses the host.
	if o.checkAddrs([]netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("127.0.0.1")}, nil) == nil {
		t.Error("mixed addresses allowed")
	}
	// The test escape hatch allows loopback only.
	o.allowLoopback = true
	if o.checkAddrs([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil) != nil ||
		o.checkAddrs([]netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil) == nil {
		t.Error("allowLoopback must allow loopback and nothing else")
	}
}

// A redirect from an allowed source to an internal address is refused
// before the dial, even with the loopback test escape hatch on.
func TestRunRefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/v2/", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	src, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://")+"/team/app", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, src, newRegistry(t, true), password)
	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, "internal address 169.254.169.254") {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
}

func TestRunRecoversPanic(t *testing.T) {
	e := newEnv(t, newRegistry(t, false), newRegistry(t, true), password)
	var out bytes.Buffer
	term := filepath.Join(e.dir, "termination-log")
	// A nil getenv panics during setup.
	code := run(context.Background(), []string{"--spec", e.spec}, &out, term, e.opts, nil)
	msg, err := os.ReadFile(term) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if code != syncspec.ExitSyncFailed || !strings.Contains(string(msg), `"errors":["internal error"]`) {
		t.Fatalf("exit %d: %s", code, msg)
	}
}

func TestRunDNSErrors(t *testing.T) {
	stubWait(t)
	src := newRegistry(t, false)
	cases := []struct {
		err  *net.DNSError
		code int
	}{
		{&net.DNSError{Err: dnsTimeout, IsTimeout: true}, syncspec.ExitSyncFailed},
		{&net.DNSError{Err: "server misbehaving", IsTemporary: true}, syncspec.ExitSyncFailed},
		// Without a proxy nothing else can resolve the name.
		{&net.DNSError{Err: dnsNotFound, IsNotFound: true}, syncspec.ExitSyncFailed},
	}
	for _, tc := range cases {
		t.Run(tc.err.Err, func(t *testing.T) {
			e := newEnv(t, src, newRegistry(t, true), password)
			e.opts.allowLoopback = false
			e.opts.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, tc.err }
			e.writeSpec(t, exampleTargetRepo, `"allowedSources":["registry.example.internal"]`)
			code, out, msg := e.run(t)
			if code != tc.code || !strings.Contains(msg, "resolve") || out != "" {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
		})
	}
}

func TestTargetAuthKeyChoice(t *testing.T) {
	const host = "registry.example.internal"
	entry := func(pass string) string {
		return fmt.Sprintf(`{"auth":%q}`, base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}
	cases := []struct {
		name string
		keys map[string]string
		want string
	}{
		{"exact key wins", map[string]string{"https://" + host + "/v1/": "a", host: "b", "http://" + host: "c"}, "b"},
		{"sorted when no exact key", map[string]string{"https://" + host + "/v1/": "a", "http://" + host: "c"}, "c"},
		{"case-insensitive", map[string]string{"https://REGISTRY.Example.internal/v1/": "a"}, "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := make([]string, 0, len(tc.keys))
			for k, p := range tc.keys {
				parts = append(parts, strconv.Quote(k)+":"+entry(p))
			}
			path := filepath.Join(t.TempDir(), "auth.json")
			if err := os.WriteFile(path, []byte(`{"auths":{`+strings.Join(parts, ",")+`}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			// Repeat: map order must not change the choice.
			for range 20 {
				a, err := dockerAuth(path, host, "target")
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := a.Authorization()
				if err != nil || cfg.Password != tc.want {
					t.Fatalf("password %q, want %q (%v)", cfg.Password, tc.want, err)
				}
			}
		})
	}
}

// The source needs basic auth: it syncs with the mounted credentials and
// fails without them; the password never reaches the outputs.
func TestRunSourceCredentials(t *testing.T) {
	src, dst := newRegistryPass(t, sourcePass), newRegistry(t, true)
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"v1.0.0", v110} {
		if err := remote.Write(src.Tag(tag), img, remote.WithAuth(&authn.Basic{Username: user, Password: sourcePass})); err != nil {
			t.Fatal(err)
		}
	}

	e := newEnv(t, src, dst, password)
	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, "list source tags") {
		t.Fatalf("anonymous: exit %d: %s\n%s", code, msg, out)
	}
	assertNoSecrets(t, out, msg)

	e.opts.sourceAuth = filepath.Join(e.dir, "source.json")
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + sourcePass))
	e.write(t, e.opts.sourceAuth, fmt.Sprintf(`{"auths":{"https://%s/v1/":{"auth":%q}}}`, src.RegistryStr(), auth))
	code, out, msg = e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":2`) {
		t.Fatalf("with credentials: exit %d: %s\n%s", code, msg, out)
	}
	assertNoSecrets(t, out, msg)
}

// The source redirects blobs to a host that records the Authorization
// header: the source credentials must not follow the redirect.
func TestRunSourceCredentialsNotSentOnRedirect(t *testing.T) {
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	var hits atomic.Int32
	var leaked atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if a := r.Header.Get("Authorization"); a != "" {
			leaked.Store(a)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != sourcePass {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
			http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // test redirect
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	src, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://")+"/team/app", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(src.Tag("v1.0.0"), img, remote.WithAuth(&authn.Basic{Username: user, Password: sourcePass})); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, src, newRegistry(t, true), password)
	e.opts.sourceAuth = filepath.Join(e.dir, "source.json")
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + sourcePass))
	e.write(t, e.opts.sourceAuth, fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, src.RegistryStr(), auth))
	code, out, msg := e.run(t)
	if code != syncspec.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	if hits.Load() == 0 {
		t.Fatal("no blob request reached the redirect target")
	}
	if a := leaked.Load(); a != nil {
		t.Fatalf("Authorization sent to the redirect host: %v", a)
	}
}

func TestSourceAuthDockerHub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"auths":{"https://index.docker.io/v1/":{"auth":%q}}}`, auth)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"docker.io", "index.docker.io", "registry-1.docker.io"} {
		a, err := dockerAuth(path, host, "source")
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if cfg, err := a.Authorization(); err != nil || cfg.Password != password {
			t.Fatalf("%s: %v", host, err)
		}
	}
}

// A source served over TLS with its own CA syncs only when the source CA
// file is mounted. The target transport does not trust that CA.
func TestRunSourceCA(t *testing.T) {
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	src, err := name.NewRepository(strings.TrimPrefix(srv.URL, "https://")+"/team/app", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(src.Tag("v1.0.0"), img, remote.WithTransport(tr)); err != nil {
		t.Fatal(err)
	}

	e := newEnv(t, src, newRegistry(t, true), password)
	code, out, msg := e.run(t)
	if code != syncspec.ExitSyncFailed || !strings.Contains(msg, "list source tags") {
		t.Fatalf("without CA: exit %d: %s\n%s", code, msg, out)
	}

	// The target transport does not trust the source CA.
	_, dstT, err := transports(e.opts, nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{Transport: dstT}).Get(srv.URL + "/v2/"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("target transport must reject the source certificate, got %v", err)
	}

	e.opts.sourceCA = filepath.Join(e.dir, "source-ca.crt")
	e.write(t, e.opts.sourceCA, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	code, out, msg = e.run(t)
	if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":1`) {
		t.Fatalf("with CA: exit %d: %s\n%s", code, msg, out)
	}
}

func TestRunAuditsIgnoredMutation(t *testing.T) {
	src, dst := newRegistry(t, false), newRegistry(t, true)
	pushImages(t, src, "v1.0.0")
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(dst.Tag("v1.0.0"), img, remote.WithAuth(&authn.Basic{Username: user, Password: password})); err != nil {
		t.Fatal(err)
	}
	kept, _ := img.Digest()
	upstream, err := remote.Head(src.Tag("v1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, src, dst, password)
	b, _ := os.ReadFile(e.spec) //nolint:gosec // test temp dir
	e.write(t, e.spec, strings.Replace(string(b), `"Fail"`, `"Ignore"`, 1))

	code, out, msg := e.run(t)
	lines := auditLines(t, out)
	if code != syncspec.ExitOK || len(lines) != 1 {
		t.Fatalf("exit %d: %s\n%s", code, msg, out)
	}
	l := lines[0]
	if l.Action != "mutation-ignored" || l.UpstreamDigest != upstream.Digest.String() ||
		l.Source != src.String()+":v1.0.0@"+upstream.Digest.String() || l.Target != dst.String()+":v1.0.0@"+kept.String() {
		t.Fatalf("audit line %+v", l)
	}
	if !strings.Contains(msg, kept.String()) || strings.Contains(msg, upstream.Digest.String()) {
		t.Fatalf("report must list the kept digest: %s", msg)
	}
}

// stubWait counts backoff waits without sleeping.
func stubWait(t *testing.T) *int {
	t.Helper()
	orig := twregistry.Wait
	n := 0
	twregistry.Wait = func(context.Context, time.Duration) error { n++; return nil }
	t.Cleanup(func() { twregistry.Wait = orig })
	return &n
}

// A pod's DNS traffic can be rejected until its NetworkPolicy is
// programmed. Temporary lookup errors are retried before the answer is
// cached; a missing name and a refused address are not.
func TestLookupRetry(t *testing.T) {
	public := []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}
	refused := &net.DNSError{Err: "read udp: connection refused", IsTemporary: true}
	cases := []struct {
		name   string
		errs   []error
		ips    []net.IPAddr
		proxy  bool
		calls  int
		waits  int
		wantOK bool
	}{
		{"temporary twice", []error{refused, &net.DNSError{Err: dnsTimeout, IsTimeout: true}}, public, false, 3, 2, true},
		{"temporary behind proxy", []error{refused}, public, true, 2, 1, true},
		{"not found", []error{&net.DNSError{Err: dnsNotFound, IsNotFound: true}}, nil, false, 1, 0, false},
		{"refused address", nil, []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, false, 1, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			waits := stubWait(t)
			calls := 0
			o := options{lookup: cachedLookup(func(context.Context, string) ([]net.IPAddr, error) {
				calls++
				if calls <= len(tc.errs) {
					return nil, tc.errs[calls-1]
				}
				return tc.ips, nil
			}, twregistry.NewWindow())}
			for range 2 { // the second check hits the cache
				err := o.checkHost(context.Background(), "registry.example.internal", tc.proxy, nil)
				if (err == nil) != tc.wantOK {
					t.Fatalf("err = %v", err)
				}
			}
			if calls != tc.calls || *waits != tc.waits {
				t.Fatalf("%d lookups, %d waits; want %d, %d", calls, *waits, tc.calls, tc.waits)
			}
		})
	}
}

// Temporary lookup errors are retried for the whole backoff schedule and
// then fail the run as transient.
func TestLookupRetryGivesUp(t *testing.T) {
	waits := stubWait(t)
	calls := 0
	o := options{lookup: cachedLookup(func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return nil, &net.DNSError{Err: dnsTimeout, IsTimeout: true}
	}, twregistry.NewWindow())}
	// The failure is not cached while the window is open: the next check
	// tries again.
	for i := 1; i <= 2; i++ {
		if err := o.checkHost(context.Background(), "registry.example.internal", false, nil); !errors.As(err, new(transientError)) {
			t.Fatalf("err = %v, want transient", err)
		}
		if calls != i*(len(twregistry.Backoff)+1) || *waits != i*len(twregistry.Backoff) {
			t.Fatalf("%d lookups, %d waits", calls, *waits)
		}
	}
}

// A host waiting for a retry does not block lookups of other hosts.
func TestLookupRetryUnlocked(t *testing.T) {
	var o options
	orig := twregistry.Wait
	twregistry.Wait = func(ctx context.Context, _ time.Duration) error {
		_, err := o.lookup(ctx, "other.example.internal")
		return err
	}
	t.Cleanup(func() { twregistry.Wait = orig })
	failed := false
	o.lookup = cachedLookup(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "registry.example.internal" && !failed {
			failed = true
			return nil, &net.DNSError{Err: dnsTimeout, IsTimeout: true}
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}, twregistry.NewWindow())
	if _, err := o.lookup(context.Background(), "registry.example.internal"); err != nil {
		t.Fatal(err)
	}
}

func TestSelectionReport(t *testing.T) {
	res := sync.Result{Stats: &twtags.Stats{Listed: 4, Prerelease: 2, Filtered: 2, Missing: []string{"a", "b", "c", "d", "e", "f", "g"}}}
	r := summarize(res)
	got, err := syncspec.ParseReport(string(encode(r)))
	if err != nil {
		t.Fatal(err)
	}
	want := &syncspec.Selection{Listed: 4, Filtered: 2, Prerelease: 2, Missing: 7, MissingTags: []string{"a", "b", "c", "d", "e"}}
	if !reflect.DeepEqual(got.Selection, want) {
		t.Errorf("got %+v, want %+v", got.Selection, want)
	}
	if got := summarize(sync.Result{}); got.Selection != nil {
		t.Errorf("no stats, selection %+v", got.Selection)
	}

	// Names are dropped, the count stays, when the message is full.
	r.Errors = []string{strings.Repeat("e", 200)}
	for i := range 200 {
		r.Synced = append(r.Synced, syncedTag{Tag: fmt.Sprintf("v1.0.%d-%s", i, strings.Repeat("x", 100)), Digest: "sha256:" + strings.Repeat("c", 64)})
	}
	r.Selection.MissingTags = []string{strings.Repeat("m", 128), strings.Repeat("n", 128)}
	b := encode(r)
	got, err = syncspec.ParseReport(string(b))
	if err != nil || len(b) > maxTermination || got.Selection == nil || got.Selection.Missing != 7 {
		t.Fatalf("%v, %d bytes: %s", err, len(b), b)
	}
}

// A Harbor target deletes tags through the Harbor API with the mounted
// target credentials; other targets keep the OCI tag delete.
func TestLoadHarborDeleteTag(t *testing.T) {
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		got = r.Method + " " + r.URL.EscapedPath() + " " + u + ":" + p
	}))
	t.Cleanup(srv.Close)
	dst, err := name.NewRepository(strings.TrimPrefix(srv.URL, "https://")+"/team/app", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	src := newRegistry(t, false)
	extra := `"allowedSources":[` + strconv.Quote(src.RegistryStr()) + `]`

	e := newEnv(t, src, dst, password)
	_, req, err := load(context.Background(), e.spec, e.opts, func(k string) string { return e.vars[k] })
	if err != nil || req.DeleteTag != nil {
		t.Fatalf("OCI target: DeleteTag set or %v", err)
	}

	// The Harbor API is https only; trust the test server as the target CA.
	e.opts.targetCA = filepath.Join(e.dir, "ca.crt")
	e.write(t, e.opts.targetCA, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	e.writeSpec(t, src.String(), `"targetFlavor":"Harbor",`+extra)
	_, req, err = load(context.Background(), e.spec, e.opts, func(k string) string { return e.vars[k] })
	if err != nil || req.DeleteTag == nil {
		t.Fatalf("Harbor target: DeleteTag nil or %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := req.DeleteTag(context.Background(), "v1", digest); err != nil {
		t.Fatal(err)
	}
	want := "DELETE /api/v2.0/projects/team/repositories/app/artifacts/" + digest + "/tags/v1 " + user + ":" + password
	if got != want {
		t.Fatalf("request %q, want %q", got, want)
	}
}
