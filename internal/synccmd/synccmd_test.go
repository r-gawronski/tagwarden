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
	"encoding/base64"
	"encoding/json"
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
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/r-gawronski/tagwarden/internal/syncspec"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	v110          = "v1.1.0"
	user          = "pusher"
	password      = "s3cret-push-pass"
	proxyPassword = "s3cret-proxy-pass"
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
		Synced: []syncedTag{{v110, "sha256:" + strings.Repeat("a", 64)}, {"v1.0.0", "sha256:" + strings.Repeat("b", 64)}},
		Errors: []string{"v0.9.0: resolve source tag: not found"},
	}
	golden(t, "report.golden", encode(r))
}

func TestEncodeReportTruncates(t *testing.T) {
	var r report
	for i := range 200 {
		r.Synced = append(r.Synced, syncedTag{fmt.Sprintf("v1.0.%d-%s", 200-i, strings.Repeat("x", 100)), "sha256:" + strings.Repeat("c", 64)})
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
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); auth && (!ok || u != user || p != password) {
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
func (e *env) run(t *testing.T) (int, string, string) {
	t.Helper()
	var out bytes.Buffer
	term := filepath.Join(e.dir, "termination-log")
	code := run(context.Background(), []string{"--spec", e.spec}, &out, term, e.opts, func(k string) string { return e.vars[k] })
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
	for _, o := range outputs {
		for _, s := range []string{password, proxyPassword, auth} {
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
		if l.TS == "" || l.Mirror != "team-a/app" || l.Action != "copied" || l.Error != "" ||
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
	src, err := name.NewRepository("registry.example.internal/team/app")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, src, newRegistry(t, true), password)
	e.vars["HTTPS_PROXY"] = proxy.URL
	// The Job cannot resolve upstream names; the proxy does.
	e.opts.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
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
		"empty CA":       func(e *env) { e.opts.proxyCA = e.spec },
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
		{"registry.example.internal/team/app", `"other.example.internal"`, "", "not in allowedSources"},
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
		if got := allowedSource(tc.host, tc.allowed); got != tc.want {
			t.Errorf("allowedSource(%q, %v) = %v", tc.host, tc.allowed, got)
		}
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
	src := newRegistry(t, false)
	cases := []struct {
		err  *net.DNSError
		code int
	}{
		{&net.DNSError{Err: "timeout", IsTimeout: true}, syncspec.ExitSyncFailed},
		{&net.DNSError{Err: "server misbehaving", IsTemporary: true}, syncspec.ExitSyncFailed},
		// Without a proxy nothing else can resolve the name.
		{&net.DNSError{Err: "no such host", IsNotFound: true}, syncspec.ExitSyncFailed},
	}
	for _, tc := range cases {
		t.Run(tc.err.Err, func(t *testing.T) {
			e := newEnv(t, src, newRegistry(t, true), password)
			e.opts.allowLoopback = false
			e.opts.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, tc.err }
			e.writeSpec(t, "registry.example.internal/team/app", `"allowedSources":["registry.example.internal"]`)
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
				a, err := targetAuth(path, host)
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
