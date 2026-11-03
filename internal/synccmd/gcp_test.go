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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

//nolint:gosec // fake credentials
const (
	gcpSAToken     = "eyJ.gcp-projected-token.sig"
	federatedToken = "ya29.fake-federated-token"
	saAccessToken  = "ya29.fake-service-account-token"
	gcpAudience    = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tagwarden/providers/cluster"
	gcpEmail       = "tagwarden-sync@example-project.iam.gserviceaccount.com"
	notGAR         = "is not a Google Artifact Registry host"
	iamPath        = "/v1/projects/-/serviceAccounts/" + gcpEmail + ":generateAccessToken"
)

// Shared test case names and fixtures of the cloud auth tests.
const (
	tcSTSRedirect     = "STS redirect"
	tcNoTokenFile     = "no token file"
	msgProjectedToken = "projected ServiceAccount token"
	exampleTargetRepo = "registry.example.internal/team/app"
)

// gcpFakes is the Google STS and IAM Credentials APIs on one TLS server
// and a registry that accepts only the final access token.
type gcpFakes struct {
	google, gar *httptest.Server
	repo        name.Repository
	// stsStatus and iamStatus replace the success answer when non-zero.
	stsStatus, iamStatus atomic.Int32
	stsBody, iamBody     atomic.Value
	iamAuth              atomic.Value
	stsHits, iamHits     atomic.Int32
	garHits              atomic.Int32
	// want is the password the registry accepts.
	want string
}

func newGCPFakes(t *testing.T, impersonate bool) *gcpFakes {
	t.Helper()
	f := &gcpFakes{want: federatedToken}
	if impersonate {
		f.want = saAccessToken
	}
	read := func(r *http.Request) string {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s with %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}
	f.google = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/token":
			f.stsHits.Add(1)
			if r.Header.Get("Authorization") != "" {
				t.Error("STS request with an Authorization header")
			}
			f.stsBody.Store(read(r))
			switch s := int(f.stsStatus.Load()); s {
			case 0:
				_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // fake token
					"access_token": federatedToken, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
					"token_type": "Bearer", "expires_in": 3599,
				})
			case http.StatusTemporaryRedirect:
				http.Redirect(w, r, f.gar.URL+"/stolen", s)
			default:
				// STS may echo request details in the description.
				w.WriteHeader(s)
				_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"token %s"}`, gcpSAToken)
			}
		case iamPath:
			f.iamHits.Add(1)
			f.iamAuth.Store(r.Header.Get("Authorization"))
			f.iamBody.Store(read(r))
			if s := int(f.iamStatus.Load()); s != 0 {
				w.WriteHeader(s)
				_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"denied for %s","status":"PERMISSION_DENIED"}}`, s, federatedToken)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": saAccessToken, "expireTime": "2030-01-01T01:00:00Z"})
		default:
			t.Errorf("unexpected Google request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.google.Close)
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	f.gar = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.garHits.Add(1)
		if u, p, ok := r.BasicAuth(); !ok || u != garUser || p != f.want {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.gar.Close)
	var err error
	if f.repo, err = name.NewRepository(strings.TrimPrefix(f.gar.URL, "https://")+"/project/team/app", name.StrictValidation); err != nil {
		t.Fatal(err)
	}
	return f
}

// remoteOpts reach the fake registry directly, as the test.
func (f *gcpFakes) remoteOpts() []remote.Option {
	pool := x509.NewCertPool()
	pool.AddCert(f.gar.Certificate())
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return []remote.Option{remote.WithTransport(tr), remote.WithAuth(&authn.Basic{Username: garUser, Password: f.want})}
}

// gcpEnv writes the token file, points the Job at the fakes, trusts them
// through the proxy CA file and sets auth ("targetAuth" or "sourceAuth").
func (f *gcpFakes) gcpEnv(t *testing.T, e *env, source name.Repository, auth string) {
	t.Helper()
	e.opts.gcpToken = filepath.Join(e.dir, "gcp-token")
	e.write(t, e.opts.gcpToken, gcpSAToken+"\n")
	e.opts.gcpSTS, e.opts.gcpIAM = f.google.URL, f.google.URL
	e.opts.proxyCA = filepath.Join(e.dir, "proxy-ca.crt")
	e.write(t, e.opts.proxyCA, string(pem.EncodeToMemory(&pem.Block{Type: certPEM, Bytes: f.google.Certificate().Raw})))
	email := ""
	if f.want == saAccessToken {
		email = gcpEmail
	}
	e.writeSpec(t, source.String(), fmt.Sprintf(`"allowedSources":[%s],%q:%q,"gcp":{"audience":%q,"serviceAccountEmail":%q}`,
		strconv.Quote(source.RegistryStr()), auth, syncspec.AuthGCPWorkloadIdentity, gcpAudience, email))
}

func (f *gcpFakes) assertRequests(t *testing.T) {
	t.Helper()
	body, _ := f.stsBody.Load().(string)
	var sts stsRequest
	var fields map[string]any
	_ = json.Unmarshal([]byte(body), &sts)
	_ = json.Unmarshal([]byte(body), &fields)
	want := stsRequest{ //nolint:gosec // fake token
		GrantType: "urn:ietf:params:oauth:grant-type:token-exchange", Audience: gcpAudience,
		Scope: "https://www.googleapis.com/auth/cloud-platform", RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt", SubjectToken: gcpSAToken,
	}
	if sts != want || len(fields) != 6 {
		t.Fatalf("STS body %v", sts)
	}
	if f.want == federatedToken {
		if f.iamHits.Load() != 0 {
			t.Fatal("impersonation without serviceAccountEmail")
		}
		return
	}
	iam, _ := f.iamBody.Load().(string)
	if iam != `{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}` ||
		f.iamAuth.Load() != "Bearer "+federatedToken {
		t.Fatalf("IAM request %v with %v", iam, f.iamAuth.Load())
	}
}

func assertNoGCPTokens(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, s := range []string{gcpSAToken, federatedToken, saAccessToken, "gcp-projected-token", "fake-federated", "fake-service-account"} {
			if strings.Contains(o, s) {
				t.Fatalf("token in output: %s", o)
			}
		}
	}
}

func TestRunGCPTarget(t *testing.T) {
	for _, impersonate := range []bool{false, true} {
		t.Run(fmt.Sprintf("impersonate=%v", impersonate), func(t *testing.T) {
			f := newGCPFakes(t, impersonate)
			src := newRegistry(t, false)
			pushImages(t, src, "v1.0.0", v110)
			e := newEnv(t, src, f.repo, password)
			e.opts.targetAuth = filepath.Join(e.dir, "missing", "auth.json")
			f.gcpEnv(t, e, src, "targetAuth")

			code, out, msg := e.run(t)
			if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":2`) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			f.assertRequests(t)
			tags, err := remote.List(f.repo, f.remoteOpts()...)
			if err != nil || len(tags) != 2 {
				t.Fatalf("target tags %v: %v", tags, err)
			}
			assertNoGCPTokens(t, out, msg)
		})
	}
}

func TestRunGCPSource(t *testing.T) {
	for _, impersonate := range []bool{false, true} {
		t.Run(fmt.Sprintf("impersonate=%v", impersonate), func(t *testing.T) {
			f := newGCPFakes(t, impersonate)
			img, err := random.Image(64, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(f.repo.Tag("v1.0.0"), img, f.remoteOpts()...); err != nil {
				t.Fatal(err)
			}
			e := newEnv(t, f.repo, newRegistry(t, true), password)
			f.gcpEnv(t, e, f.repo, "sourceAuth")

			code, out, msg := e.run(t)
			if code != syncspec.ExitOK || !strings.Contains(msg, `"copied":1`) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			f.assertRequests(t)
			assertNoGCPTokens(t, out, msg)
		})
	}
}

func TestRunGCPErrors(t *testing.T) {
	cases := map[string]struct {
		impersonate bool
		setup       func(f *gcpFakes, e *env)
		code        int
		want        string
	}{
		"STS invalid grant": {
			false, func(f *gcpFakes, _ *env) { f.stsStatus.Store(http.StatusBadRequest) },
			syncspec.ExitConfig, "target credentials: Google STS token exchange: HTTP 400 invalid_grant",
		},
		"STS rate limited": {
			false, func(f *gcpFakes, _ *env) { f.stsStatus.Store(http.StatusTooManyRequests) },
			syncspec.ExitSyncFailed, "Google STS token exchange: HTTP 429",
		},
		"STS unavailable": {
			false, func(f *gcpFakes, _ *env) { f.stsStatus.Store(http.StatusServiceUnavailable) },
			syncspec.ExitSyncFailed, "Google STS token exchange: HTTP 503",
		},
		tcSTSRedirect: {
			false, func(f *gcpFakes, _ *env) { f.stsStatus.Store(http.StatusTemporaryRedirect) },
			syncspec.ExitConfig, "Google STS token exchange: HTTP 307",
		},
		"IAM permission denied": {
			true, func(f *gcpFakes, _ *env) { f.iamStatus.Store(http.StatusForbidden) },
			syncspec.ExitConfig, "target credentials: Google IAM generateAccessToken: HTTP 403 PERMISSION_DENIED",
		},
		"IAM unavailable": {
			true, func(f *gcpFakes, _ *env) { f.iamStatus.Store(http.StatusInternalServerError) },
			syncspec.ExitSyncFailed, "Google IAM generateAccessToken: HTTP 500 PERMISSION_DENIED",
		},
		tcNoTokenFile: {
			false, func(_ *gcpFakes, e *env) { e.opts.gcpToken = filepath.Join(e.dir, "missing", "token") },
			syncspec.ExitConfig, msgProjectedToken,
		},
	}
	for tcName, tc := range cases {
		t.Run(tcName, func(t *testing.T) {
			f := newGCPFakes(t, tc.impersonate)
			src := newRegistry(t, false)
			e := newEnv(t, src, f.repo, password)
			f.gcpEnv(t, e, src, "targetAuth")
			tc.setup(f, e)
			code, out, msg := e.run(t)
			if code != tc.code || !strings.Contains(msg, tc.want) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			if tcName == tcSTSRedirect && f.garHits.Load() != 0 {
				t.Fatal("the token request followed the redirect")
			}
			assertNoGCPTokens(t, out, msg)
		})
	}
}

// Tokens go only to Artifact Registry hosts: anything else is a config
// error before any token request.
func TestRunGCPRefusesHosts(t *testing.T) {
	for tcName, target := range map[string]string{
		"non-GAR target":   exampleTargetRepo,
		"other gcr.io":     "mirror.gcr.io/team/app",
		"non-Docker GAR":   "europe-west1-npm.pkg.dev/project/team/app",
		"look-alike host":  "europe-west1-docker.pkg.dev.example.internal/team/app",
		"non-default port": "europe-west1-docker.pkg.dev:5000/project/team/app",
	} {
		t.Run(tcName, func(t *testing.T) {
			f := newGCPFakes(t, true)
			src := newRegistry(t, false)
			e := newEnv(t, src, f.repo, password)
			e.target = target
			f.gcpEnv(t, e, src, "targetAuth")
			code, out, msg := e.run(t)
			if code != syncspec.ExitConfig || !strings.Contains(msg, "target credentials: ") || !strings.Contains(msg, notGAR) {
				t.Fatalf("exit %d: %s\n%s", code, msg, out)
			}
			if f.stsHits.Load() != 0 || f.iamHits.Load() != 0 || f.garHits.Load() != 0 {
				t.Fatal("a token request was sent")
			}
		})
	}
}
