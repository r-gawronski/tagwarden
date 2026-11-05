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

package registry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

var errAny = errors.New("any error")

// robotUser and robotPass are test Harbor robot credentials; "$" must
// survive basic auth.
const (
	robotUser = "robot$push"
	robotPass = "s3cret"
)

// digest is the artifact the tests delete a tag from.
var digest = "sha256:" + strings.Repeat("ab", 32)

// harborServer starts a TLS server and returns a transport that sends every
// request for example.com to it. ggcr picks http for loopback addresses, so
// the repository uses example.com (a SAN of the httptest certificate) to keep
// the https scheme a real registry gets.
func harborServer(t *testing.T, h http.HandlerFunc) http.RoundTripper {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return tr
}

func TestHarborDeleteTag(t *testing.T) {
	repo, err := name.NewRepository("example.com/mirror/docker.io/library/nginx")
	if err != nil {
		t.Fatal(err)
	}
	auth := authn.FromConfig(authn.AuthConfig{Username: robotUser, Password: robotPass})
	for _, tc := range []struct {
		name   string
		status int
		want   error // nil, ErrTagNotFound or errAny
	}{
		{name: "deleted", status: http.StatusOK},
		{name: "tag not on digest", status: http.StatusNotFound, want: ErrTagNotFound},
		{name: "forbidden", status: http.StatusForbidden, want: errAny},
		{name: "redirect is not followed", status: http.StatusFound, want: errAny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var method, path, user, pass string
			var calls int
			rt := harborServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				method, path = r.Method, r.URL.EscapedPath()
				user, pass, _ = r.BasicAuth()
				if tc.status == http.StatusFound {
					http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("server text password=hunter2"))
			})
			err := HarborDeleteTag(rt, auth, repo)(context.Background(), "1.31.8", digest)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case tc.want == ErrTagNotFound && !errors.Is(err, ErrTagNotFound):
				t.Fatalf("err = %v, want ErrTagNotFound", err)
			case tc.want == errAny && (err == nil || errors.Is(err, ErrTagNotFound)):
				t.Fatalf("err = %v, want a non-sentinel error", err)
			}
			if err != nil {
				for _, s := range []string{robotPass, "hunter2"} {
					if strings.Contains(err.Error(), s) {
						t.Errorf("error %q leaks %q", err, s)
					}
				}
			}
			if calls != 1 {
				t.Fatalf("calls = %d, want 1", calls)
			}
			wantPath := "/api/v2.0/projects/mirror/repositories/docker.io%252Flibrary%252Fnginx/artifacts/" + digest + "/tags/1.31.8"
			if method != http.MethodDelete || path != wantPath {
				t.Errorf("request = %s %s, want DELETE %s", method, path, wantPath)
			}
			if user != robotUser || pass != robotPass {
				t.Errorf("basic auth = %q/%q", user, pass)
			}
		})
	}
}

func TestHarborDeleteTagRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo string
		auth authn.Authenticator
	}{
		{name: "missing password", repo: "example.com/mirror/nginx", auth: authn.FromConfig(authn.AuthConfig{Username: robotUser})},
		{name: "anonymous", repo: "example.com/mirror/nginx", auth: authn.Anonymous},
		{name: "no path after project", repo: "example.com/mirror", auth: authn.FromConfig(authn.AuthConfig{Username: "u", Password: "p"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			rt := harborServer(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
			repo, err := name.NewRepository(tc.repo)
			if err != nil {
				t.Fatal(err)
			}
			if err := HarborDeleteTag(rt, tc.auth, repo)(context.Background(), "1.0", digest); err == nil {
				t.Fatal("err = nil, want an error")
			}
			if calls != 0 {
				t.Fatalf("calls = %d, want 0", calls)
			}
		})
	}
}

// ggcr's Scheme() guesses http for private hosts. The delete must still use
// TLS, or it sends the credentials in clear text.
func TestHarborDeleteTagUsesHTTPSForPrivateHosts(t *testing.T) {
	auth := authn.FromConfig(authn.AuthConfig{Username: robotUser, Password: robotPass})
	for _, host := range []string{"10.20.0.5", "harbor.local", "localhost:8443"} {
		t.Run(host, func(t *testing.T) {
			repo, err := name.NewRepository(host + "/mirror/docker.io/library/nginx")
			if err != nil {
				t.Fatal(err)
			}
			var tls bool
			rt := harborServer(t, func(w http.ResponseWriter, r *http.Request) { tls = r.TLS != nil })
			// The httptest certificate does not cover host; verify it as
			// example.com so the handshake still checks the chain.
			rt.(*http.Transport).TLSClientConfig.ServerName = "example.com"
			if err := HarborDeleteTag(rt, auth, repo)(context.Background(), "1.0", digest); err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !tls {
				t.Fatal("request was not sent over TLS")
			}
		})
	}
}
